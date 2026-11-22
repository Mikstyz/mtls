CREATE TABLE user_profile_image_appeals (
    case_id UUID PRIMARY KEY REFERENCES user_profile_image_decisions(case_id) ON DELETE CASCADE,
    statement TEXT NOT NULL CHECK (char_length(statement) BETWEEN 1 AND 1000 AND btrim(statement)<>''),
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    outcome TEXT CHECK (outcome IN ('upheld','reversed')),
    reviewed_by UUID,
    reviewed_at TIMESTAMPTZ,
    CHECK (num_nonnulls(outcome,reviewed_by,reviewed_at) IN (0,3))
);

CREATE INDEX user_profile_image_appeals_pending_idx ON user_profile_image_appeals(submitted_at,case_id)
    WHERE outcome IS NULL;

CREATE OR REPLACE FUNCTION user_profile_image_blocked(owner UUID, media UUID) RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT EXISTS (
        SELECT 1 FROM public.user_profile_image_reports r
        JOIN public.user_profile_image_decisions d USING(case_id)
        LEFT JOIN public.user_profile_image_appeals a USING(case_id)
        WHERE r.owner_id=owner AND r.media_id=media AND d.action='remove'
            AND a.outcome IS DISTINCT FROM 'reversed'
    )
$$;

CREATE FUNCTION user_profile_image_notices(owner UUID)
RETURNS TABLE(case_id UUID,slot TEXT,media_id UUID,reason TEXT,decided_at TIMESTAMPTZ,appeal TEXT)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT r.case_id,r.slot,r.media_id,r.reason,d.decided_at,
        CASE WHEN a.case_id IS NOT NULL THEN COALESCE(a.outcome,'pending') END
    FROM public.user_profile_image_reports r
    JOIN public.user_profile_image_decisions d USING(case_id)
    LEFT JOIN public.user_profile_image_appeals a USING(case_id)
    WHERE r.owner_id=owner AND d.action='remove'
        AND EXISTS (SELECT 1 FROM public.users WHERE id=owner)
    ORDER BY d.decided_at DESC,r.case_id LIMIT 50
$$;

CREATE FUNCTION user_submit_profile_image_appeal(owner UUID,target UUID,explanation TEXT)
RETURNS INTEGER LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    previous TEXT;
BEGIN
    IF explanation IS NULL OR btrim(explanation)='' OR char_length(explanation)>1000 THEN RETURN 400; END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(owner::text,0));
    PERFORM 1 FROM public.user_profile_image_reports r
    JOIN public.user_profile_image_decisions d USING(case_id)
    WHERE r.case_id=target AND r.owner_id=owner AND d.action='remove'
        AND EXISTS (SELECT 1 FROM public.users WHERE id=owner)
    FOR UPDATE OF r;
    IF NOT FOUND THEN RETURN 404; END IF;

    SELECT statement INTO previous FROM public.user_profile_image_appeals WHERE case_id=target;
    IF FOUND THEN
        IF previous=explanation THEN RETURN 204; END IF;
        RETURN 409;
    END IF;

    INSERT INTO public.user_profile_image_appeals(case_id,statement) VALUES(target,explanation);
    RETURN 201;
END;
$$;

CREATE FUNCTION user_profile_image_appeal_queue(actor UUID)
RETURNS TABLE(case_id UUID,owner_id UUID,slot TEXT,media_id UUID,reason TEXT,statement TEXT,submitted_at TIMESTAMPTZ)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT r.case_id,r.owner_id,r.slot,r.media_id,r.reason,a.statement,a.submitted_at
    FROM public.user_profile_image_appeals a
    JOIN public.user_profile_image_reports r USING(case_id)
    JOIN public.user_profile_image_decisions d USING(case_id)
    WHERE a.outcome IS NULL AND r.owner_id<>actor AND r.reporter_id IS DISTINCT FROM actor AND d.actor_id<>actor
        AND EXISTS (SELECT 1 FROM public.users WHERE id=actor)
        AND EXISTS (SELECT 1 FROM public.users WHERE id=r.owner_id)
    ORDER BY a.submitted_at,r.case_id LIMIT 50
$$;

CREATE FUNCTION user_review_profile_image_appeal(actor UUID,target UUID,result TEXT)
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

REVOKE ALL ON FUNCTION user_profile_image_notices(UUID),user_submit_profile_image_appeal(UUID,UUID,TEXT),
    user_profile_image_appeal_queue(UUID),user_review_profile_image_appeal(UUID,UUID,TEXT) FROM PUBLIC;
