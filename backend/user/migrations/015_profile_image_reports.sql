CREATE TABLE user_profile_image_reports (
    case_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reporter_id UUID,
    request_id UUID,
    owner_id UUID NOT NULL,
    slot TEXT NOT NULL CHECK (slot IN ('avatar','banner')),
    media_id UUID NOT NULL,
    reason TEXT NOT NULL CHECK (reason IN ('spam','harassment','consent','age_safety','other')),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','reviewing','resolved','dismissed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK ((reporter_id IS NULL)=(request_id IS NULL)),
    UNIQUE (reporter_id,request_id),
    UNIQUE (reporter_id,owner_id,slot,media_id)
);

CREATE INDEX user_profile_image_reports_recent_idx ON user_profile_image_reports(reporter_id,created_at DESC);
CREATE INDEX user_profile_image_reports_owner_idx ON user_profile_image_reports(owner_id);

CREATE FUNCTION user_report_profile_image(actor UUID, operation UUID, target UUID, target_slot TEXT, target_media UUID, category TEXT)
RETURNS INTEGER LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    prior public.user_profile_image_reports%ROWTYPE;
BEGIN
    IF actor IS NULL OR operation IS NULL OR target IS NULL OR target_media IS NULL OR actor=target
        OR target_slot IS NULL OR target_slot NOT IN ('avatar','banner')
        OR category IS NULL OR category NOT IN ('spam','harassment','consent','age_safety','other')
    THEN RETURN 400; END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(actor::text,0));
    PERFORM 1 FROM public.users WHERE id=actor FOR SHARE;
    IF NOT FOUND THEN RETURN 404; END IF;

    SELECT * INTO prior FROM public.user_profile_image_reports WHERE reporter_id=actor AND request_id=operation;
    IF FOUND THEN
        IF prior.owner_id=target AND prior.slot=target_slot AND prior.media_id=target_media AND prior.reason=category
        THEN RETURN 200; END IF;
        RETURN 409;
    END IF;

    PERFORM 1 FROM public.user_profile_images i
    JOIN public.users u ON u.id=i.owner_id
    JOIN public.media_permissions p ON p.media_id=i.media_id AND p.owner_id=i.owner_id
    WHERE i.owner_id=target AND i.slot=target_slot AND i.media_id=target_media
        AND p.ready AND p.revoked_at IS NULL AND p.media_kind='photo'
    FOR SHARE OF i,u,p;
    IF NOT FOUND THEN RETURN 404; END IF;

    IF EXISTS (
        SELECT 1 FROM public.user_profile_image_reports
        WHERE reporter_id=actor AND owner_id=target AND slot=target_slot AND media_id=target_media
    ) THEN RETURN 409; END IF;

    IF EXISTS (
        SELECT 1 FROM public.user_profile_image_reports
        WHERE reporter_id=actor AND created_at>clock_timestamp()-INTERVAL '1 hour'
        LIMIT 1 OFFSET 4
    ) THEN RETURN 429; END IF;

    INSERT INTO public.user_profile_image_reports(reporter_id,request_id,owner_id,slot,media_id,reason)
    VALUES(actor,operation,target,target_slot,target_media,category);
    RETURN 201;
END;
$$;

CREATE FUNCTION user_own_profile_image_report(actor UUID, operation UUID)
RETURNS TABLE(owner_id UUID,slot TEXT,media_id UUID,reason TEXT,status TEXT,created_at TIMESTAMPTZ)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT r.owner_id,r.slot,r.media_id,r.reason,r.status,r.created_at
    FROM public.user_profile_image_reports r
    WHERE r.reporter_id=actor AND r.request_id=operation
$$;

CREATE FUNCTION user_purge_profile_image_reports(actor UUID) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
    DELETE FROM public.user_profile_image_reports WHERE owner_id=actor;
    UPDATE public.user_profile_image_reports SET reporter_id=NULL,request_id=NULL
    WHERE reporter_id=actor AND (reason IN ('age_safety','consent') OR status<>'pending');
    DELETE FROM public.user_profile_image_reports WHERE reporter_id=actor;
END;
$$;

REVOKE ALL ON FUNCTION user_report_profile_image(UUID,UUID,UUID,TEXT,UUID,TEXT),
    user_own_profile_image_report(UUID,UUID),user_purge_profile_image_reports(UUID) FROM PUBLIC;
