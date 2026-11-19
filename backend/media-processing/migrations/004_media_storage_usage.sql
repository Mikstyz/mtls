LOCK TABLE media_assets, media_uploads IN SHARE ROW EXCLUSIVE MODE;

CREATE TABLE media_storage_usage (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    assets BIGINT NOT NULL CHECK (assets >= 0),
    original_bytes BIGINT NOT NULL CHECK (original_bytes >= 0),
    unknown_assets BIGINT NOT NULL CHECK (unknown_assets >= 0 AND unknown_assets <= assets),
    owner_max_assets BIGINT,
    owner_max_bytes BIGINT,
    global_max_assets BIGINT,
    global_max_bytes BIGINT,
    CHECK (
        (owner_max_assets IS NULL AND owner_max_bytes IS NULL AND global_max_assets IS NULL AND global_max_bytes IS NULL)
        OR
        (owner_max_assets IS NOT NULL AND owner_max_assets > 0 AND owner_max_bytes IS NOT NULL AND owner_max_bytes > 0
            AND global_max_assets IS NOT NULL AND global_max_assets > 0 AND global_max_bytes IS NOT NULL AND global_max_bytes > 0)
    )
);

INSERT INTO media_storage_usage (id, assets, original_bytes, unknown_assets)
SELECT TRUE, COUNT(*), COALESCE(SUM(u.byte_size), 0), COUNT(*) FILTER (WHERE u.asset_id IS NULL)
FROM media_assets a LEFT JOIN media_uploads u ON u.asset_id = a.id;

CREATE FUNCTION media_count_asset() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE public.media_storage_usage SET assets = assets + 1, unknown_assets = unknown_assets + 1 WHERE id;
        IF NOT FOUND THEN RAISE EXCEPTION 'media storage usage missing'; END IF;
        RETURN NEW;
    END IF;

    UPDATE public.media_storage_usage SET assets = assets - 1, unknown_assets = unknown_assets - 1 WHERE id;
    IF NOT FOUND THEN RAISE EXCEPTION 'media storage usage missing'; END IF;
    RETURN OLD;
END;
$$;

CREATE FUNCTION media_count_upload() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE public.media_storage_usage SET original_bytes = original_bytes + NEW.byte_size,
            unknown_assets = unknown_assets - 1 WHERE id;
        IF NOT FOUND THEN RAISE EXCEPTION 'media storage usage missing'; END IF;
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        UPDATE public.media_storage_usage SET original_bytes = original_bytes - OLD.byte_size,
            unknown_assets = unknown_assets + 1 WHERE id;
        IF NOT FOUND THEN RAISE EXCEPTION 'media storage usage missing'; END IF;
        RETURN OLD;
    END IF;

    UPDATE public.media_storage_usage SET original_bytes = original_bytes + NEW.byte_size - OLD.byte_size WHERE id;
    IF NOT FOUND THEN RAISE EXCEPTION 'media storage usage missing'; END IF;
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION media_count_asset() FROM PUBLIC;
REVOKE ALL ON FUNCTION media_count_upload() FROM PUBLIC;

CREATE TRIGGER media_usage_asset_insert_delete
    AFTER INSERT OR DELETE ON media_assets FOR EACH ROW EXECUTE FUNCTION media_count_asset();
CREATE TRIGGER media_usage_upload_insert_delete
    AFTER INSERT OR DELETE ON media_uploads FOR EACH ROW EXECUTE FUNCTION media_count_upload();
CREATE TRIGGER media_usage_upload_size_update
    AFTER UPDATE OF byte_size ON media_uploads FOR EACH ROW EXECUTE FUNCTION media_count_upload();

-- A constrained runtime role may lock/read accounting, but cannot change it.
CREATE FUNCTION media_lock_usage() RETURNS TABLE (
    assets BIGINT, original_bytes BIGINT, unknown_assets BIGINT,
    owner_max_assets BIGINT, owner_max_bytes BIGINT, global_max_assets BIGINT, global_max_bytes BIGINT
)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT u.assets, u.original_bytes, u.unknown_assets, u.owner_max_assets, u.owner_max_bytes,
        u.global_max_assets, u.global_max_bytes
    FROM public.media_storage_usage u WHERE u.id FOR UPDATE
$$;

REVOKE ALL ON FUNCTION media_lock_usage() FROM PUBLIC;
