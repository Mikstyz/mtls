CREATE TABLE user_profile_image_holds (
    case_id UUID PRIMARY KEY REFERENCES user_profile_image_reports(case_id) ON DELETE CASCADE,
    actor_id UUID NOT NULL,
    request_id UUID NOT NULL,
    hidden_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE OR REPLACE FUNCTION user_profile_image_blocked(owner UUID, media UUID) RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT EXISTS (
        SELECT 1 FROM public.user_profile_image_reports r
        JOIN public.user_profile_image_decisions d USING(case_id)
        LEFT JOIN public.user_profile_image_appeals a USING(case_id)
        WHERE r.owner_id=owner AND r.media_id=media AND d.action='remove'
            AND a.outcome IS DISTINCT FROM 'reversed'
    ) OR EXISTS (
        SELECT 1 FROM public.user_profile_image_reports r
        JOIN public.user_profile_image_holds h USING(case_id)
        WHERE r.owner_id=owner AND r.media_id=media AND r.status='pending'
    )
$$;

CREATE OR REPLACE FUNCTION user_decide_profile_image_report(actor UUID,target UUID,operation UUID,decision TEXT)
RETURNS INTEGER LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    subject UUID;
    item public.user_profile_image_reports%ROWTYPE;
    prior public.user_profile_image_decisions%ROWTYPE;
    hold public.user_profile_image_holds%ROWTYPE;
BEGIN
    IF actor IS NULL OR target IS NULL OR operation IS NULL OR decision IS NULL OR decision NOT IN ('hide','remove','dismiss')
    THEN RETURN 400; END IF;

    SELECT owner_id INTO subject FROM public.user_profile_image_reports WHERE case_id=target;
    IF NOT FOUND OR actor=subject THEN RETURN 404; END IF;

    -- Serialize visibility changes with the owner's profile update and purge.
    PERFORM pg_advisory_xact_lock(hashtextextended(subject::text,0));
    PERFORM 1 FROM public.users WHERE id=actor FOR SHARE;
    IF NOT FOUND THEN RETURN 404; END IF;
    PERFORM 1 FROM public.users WHERE id=subject FOR SHARE;
    IF NOT FOUND THEN RETURN 404; END IF;

    SELECT * INTO item FROM public.user_profile_image_reports
    WHERE case_id=target AND reporter_id IS DISTINCT FROM actor FOR UPDATE;
    IF NOT FOUND THEN RETURN 404; END IF;

    IF decision='hide' THEN
        SELECT * INTO hold FROM public.user_profile_image_holds WHERE case_id=target;
        IF FOUND THEN
            IF hold.actor_id=actor AND hold.request_id=operation THEN RETURN 204; END IF;
            RETURN 409;
        END IF;
        IF item.status<>'pending' OR item.reason NOT IN ('consent','age_safety') THEN RETURN 409; END IF;

        INSERT INTO public.user_profile_image_holds(case_id,actor_id,request_id)
        VALUES(target,actor,operation);
        RETURN 204;
    END IF;

    SELECT * INTO prior FROM public.user_profile_image_decisions WHERE case_id=target;
    IF FOUND THEN
        IF prior.actor_id=actor AND prior.request_id=operation AND prior.action=decision THEN RETURN 204; END IF;
        RETURN 409;
    END IF;
    IF item.status<>'pending' THEN RETURN 409; END IF;

    INSERT INTO public.user_profile_image_decisions(case_id,actor_id,request_id,action)
    VALUES(target,actor,operation,decision);
    UPDATE public.user_profile_image_reports SET status=CASE decision WHEN 'remove' THEN 'resolved' ELSE 'dismissed' END
    WHERE case_id=target;
    RETURN 204;
END;
$$;

CREATE OR REPLACE FUNCTION user_profile_image_appeal_queue(actor UUID)
RETURNS TABLE(case_id UUID,owner_id UUID,slot TEXT,media_id UUID,reason TEXT,statement TEXT,submitted_at TIMESTAMPTZ)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT r.case_id,r.owner_id,r.slot,r.media_id,r.reason,a.statement,a.submitted_at
    FROM public.user_profile_image_appeals a
    JOIN public.user_profile_image_reports r USING(case_id)
    JOIN public.user_profile_image_decisions d USING(case_id)
    WHERE a.outcome IS NULL AND r.owner_id<>actor AND r.reporter_id IS DISTINCT FROM actor AND d.actor_id<>actor
        AND NOT EXISTS (
            SELECT 1 FROM public.user_profile_image_holds h WHERE h.case_id=r.case_id AND h.actor_id=actor
        )
        AND EXISTS (SELECT 1 FROM public.users WHERE id=actor)
        AND EXISTS (SELECT 1 FROM public.users WHERE id=r.owner_id)
    ORDER BY a.submitted_at,r.case_id LIMIT 50
$$;

CREATE OR REPLACE FUNCTION user_review_profile_image_appeal(actor UUID,target UUID,result TEXT)
RETURNS INTEGER LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    subject UUID;
    previous public.user_profile_image_appeals%ROWTYPE;
BEGIN
    IF result IS NULL OR result NOT IN ('upheld','reversed') THEN RETURN 400; END IF;

    SELECT owner_id INTO subject FROM public.user_profile_image_reports WHERE case_id=target;
    IF NOT FOUND OR subject=actor THEN RETURN 404; END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(subject::text,0));
    PERFORM 1 FROM public.users WHERE id=actor FOR SHARE;
    IF NOT FOUND THEN RETURN 404; END IF;
    PERFORM 1 FROM public.users WHERE id=subject FOR SHARE;
    IF NOT FOUND THEN RETURN 404; END IF;

    SELECT a.* INTO previous FROM public.user_profile_image_appeals a
    JOIN public.user_profile_image_reports r USING(case_id)
    JOIN public.user_profile_image_decisions d USING(case_id)
    WHERE a.case_id=target AND r.reporter_id IS DISTINCT FROM actor AND d.actor_id<>actor
        AND NOT EXISTS (
            SELECT 1 FROM public.user_profile_image_holds h WHERE h.case_id=r.case_id AND h.actor_id=actor
        )
    FOR UPDATE OF a;
    IF NOT FOUND THEN RETURN 404; END IF;
    IF previous.outcome IS NOT NULL THEN
        IF previous.outcome=result AND previous.reviewed_by=actor THEN RETURN 204; END IF;
        RETURN 409;
    END IF;

    UPDATE public.user_profile_image_appeals SET outcome=result,reviewed_by=actor,reviewed_at=clock_timestamp()
    WHERE case_id=target;
    RETURN 204;
END;
$$;

CREATE OR REPLACE FUNCTION user_profile_moderation_media_owner(actor UUID,target UUID,media UUID) RETURNS UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT r.owner_id
    FROM public.user_profile_image_reports r
    JOIN public.users u ON u.id=r.owner_id
    JOIN public.media_permissions p ON p.media_id=r.media_id AND p.owner_id=r.owner_id
    LEFT JOIN public.user_profile_image_decisions d ON d.case_id=r.case_id
    LEFT JOIN public.user_profile_image_appeals a ON a.case_id=r.case_id
    WHERE r.case_id=target AND r.media_id=media
        AND r.owner_id<>actor AND r.reporter_id IS DISTINCT FROM actor
        AND EXISTS (SELECT 1 FROM public.users WHERE id=actor)
        AND p.ready AND p.revoked_at IS NULL AND p.media_kind='photo'
        AND (r.status='pending' OR (
            r.status='resolved' AND d.action='remove' AND d.actor_id<>actor
            AND a.case_id IS NOT NULL AND a.outcome IS NULL
            AND NOT EXISTS (
                SELECT 1 FROM public.user_profile_image_holds h WHERE h.case_id=r.case_id AND h.actor_id=actor
            )
        ))
$$;
