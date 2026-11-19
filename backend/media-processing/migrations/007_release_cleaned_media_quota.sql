LOCK TABLE media_assets, media_uploads IN SHARE ROW EXCLUSIVE MODE;

CREATE FUNCTION media_release_removed_usage() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    reserved_bytes BIGINT;
BEGIN
    IF OLD.files_removed_at IS NOT NULL THEN
        IF NEW.files_removed_at IS DISTINCT FROM OLD.files_removed_at THEN
            RAISE EXCEPTION 'media removal cannot be reversed';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.files_removed_at IS NULL THEN
        RETURN NEW;
    END IF;

    SELECT byte_size INTO reserved_bytes FROM public.media_uploads WHERE asset_id = NEW.id;
    UPDATE public.media_storage_usage
    SET assets = assets - 1,
        original_bytes = original_bytes - COALESCE(reserved_bytes, 0),
        unknown_assets = unknown_assets - (reserved_bytes IS NULL)::INTEGER
    WHERE id;
    IF NOT FOUND THEN RAISE EXCEPTION 'media storage usage missing'; END IF;
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION media_release_removed_usage() FROM PUBLIC;

CREATE TRIGGER media_usage_release_removed
    AFTER UPDATE OF files_removed_at ON media_assets
    FOR EACH ROW EXECUTE FUNCTION media_release_removed_usage();

CREATE OR REPLACE FUNCTION media_count_asset() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.files_removed_at IS NOT NULL THEN
            RAISE EXCEPTION 'cannot insert a removed asset';
        END IF;

        UPDATE public.media_storage_usage SET assets = assets + 1, unknown_assets = unknown_assets + 1 WHERE id;
        IF NOT FOUND THEN RAISE EXCEPTION 'media storage usage missing'; END IF;
        RETURN NEW;
    END IF;

    IF OLD.files_removed_at IS NULL THEN
        UPDATE public.media_storage_usage SET assets = assets - 1, unknown_assets = unknown_assets - 1 WHERE id;
        IF NOT FOUND THEN RAISE EXCEPTION 'media storage usage missing'; END IF;
    END IF;

    RETURN OLD;
END;
$$;

CREATE OR REPLACE FUNCTION media_count_upload() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF EXISTS (SELECT 1 FROM public.media_assets WHERE id = OLD.asset_id AND files_removed_at IS NOT NULL) THEN
            RETURN OLD;
        END IF;

        UPDATE public.media_storage_usage SET original_bytes = original_bytes - OLD.byte_size,
            unknown_assets = unknown_assets + 1 WHERE id;
        IF NOT FOUND THEN RAISE EXCEPTION 'media storage usage missing'; END IF;
        RETURN OLD;
    END IF;

    IF EXISTS (SELECT 1 FROM public.media_assets WHERE id = NEW.asset_id AND files_removed_at IS NOT NULL) THEN
        RAISE EXCEPTION 'cannot modify a removed upload';
    END IF;

    IF TG_OP = 'INSERT' THEN
        UPDATE public.media_storage_usage SET original_bytes = original_bytes + NEW.byte_size,
            unknown_assets = unknown_assets - 1 WHERE id;
    ELSE
        UPDATE public.media_storage_usage SET original_bytes = original_bytes + NEW.byte_size - OLD.byte_size WHERE id;
    END IF;
    IF NOT FOUND THEN RAISE EXCEPTION 'media storage usage missing'; END IF;
    RETURN NEW;
END;
$$;

UPDATE public.media_storage_usage
SET assets = usage.assets, original_bytes = usage.bytes, unknown_assets = usage.unknown
FROM (
    SELECT COUNT(*) AS assets, COALESCE(SUM(u.byte_size), 0) AS bytes,
           COUNT(*) FILTER (WHERE u.asset_id IS NULL) AS unknown
    FROM public.media_assets a LEFT JOIN public.media_uploads u ON u.asset_id = a.id
    WHERE a.files_removed_at IS NULL
) usage
WHERE id;

CREATE INDEX media_active_owner_idx ON media_assets (owner_id)
    WHERE files_removed_at IS NULL;
