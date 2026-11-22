CREATE TABLE user_media_revocation_outbox (
    media_id UUID PRIMARY KEY REFERENCES media_permissions(media_id) ON DELETE CASCADE,
    owner_id UUID NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL
);

CREATE FUNCTION user_record_media_revocation() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
    IF NEW.revoked_at IS NULL THEN RETURN NEW; END IF;
    IF TG_OP='UPDATE' AND OLD.revoked_at IS NOT NULL THEN RETURN NEW; END IF;

    INSERT INTO public.user_media_revocation_outbox(media_id,owner_id,revoked_at)
    VALUES(NEW.media_id,NEW.owner_id,NEW.revoked_at)
    ON CONFLICT (media_id) DO NOTHING;

    RETURN NEW;
END;
$$;

INSERT INTO user_media_revocation_outbox(media_id,owner_id,revoked_at)
SELECT media_id,owner_id,revoked_at FROM media_permissions WHERE revoked_at IS NOT NULL;

CREATE TRIGGER user_record_media_revocation
    AFTER INSERT OR UPDATE OF revoked_at ON media_permissions
    FOR EACH ROW EXECUTE FUNCTION user_record_media_revocation();

REVOKE ALL ON FUNCTION user_record_media_revocation() FROM PUBLIC;
