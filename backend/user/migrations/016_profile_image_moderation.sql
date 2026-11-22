CREATE TABLE user_profile_image_decisions (
    case_id UUID PRIMARY KEY REFERENCES user_profile_image_reports(case_id) ON DELETE CASCADE,
    actor_id UUID NOT NULL,
    request_id UUID NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('remove','dismiss')),
    decided_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX user_profile_image_report_target_idx ON user_profile_image_reports(owner_id,media_id);
CREATE INDEX user_profile_image_report_pending_idx ON user_profile_image_reports(
    (reason NOT IN ('consent','age_safety')),created_at,case_id
) WHERE status='pending';

CREATE FUNCTION user_profile_image_blocked(owner UUID, media UUID) RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT EXISTS (
        SELECT 1 FROM public.user_profile_image_reports r
        JOIN public.user_profile_image_decisions d USING(case_id)
        WHERE r.owner_id=owner AND r.media_id=media AND d.action='remove'
    )
$$;

CREATE FUNCTION user_profile_image_moderation_queue(actor UUID)
RETURNS TABLE(case_id UUID,owner_id UUID,slot TEXT,media_id UUID,reason TEXT,created_at TIMESTAMPTZ)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT r.case_id,r.owner_id,r.slot,r.media_id,r.reason,r.created_at
    FROM public.user_profile_image_reports r
    JOIN public.users u ON u.id=r.owner_id
    WHERE r.status='pending' AND r.owner_id<>actor AND r.reporter_id IS DISTINCT FROM actor
        AND EXISTS (SELECT 1 FROM public.users WHERE id=actor)
    ORDER BY (r.reason NOT IN ('consent','age_safety')),r.created_at,r.case_id LIMIT 50
$$;

CREATE FUNCTION user_decide_profile_image_report(actor UUID,target UUID,operation UUID,decision TEXT)
RETURNS INTEGER LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    subject UUID;
    item public.user_profile_image_reports%ROWTYPE;
    prior public.user_profile_image_decisions%ROWTYPE;
BEGIN
    IF actor IS NULL OR target IS NULL OR operation IS NULL OR decision IS NULL OR decision NOT IN ('remove','dismiss')
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

REVOKE ALL ON FUNCTION user_profile_image_blocked(UUID,UUID),user_profile_image_moderation_queue(UUID),
    user_decide_profile_image_report(UUID,UUID,UUID,TEXT) FROM PUBLIC;
