CREATE TABLE media_purged_owners (
    owner_id UUID PRIMARY KEY
);

-- A request authenticated before final deletion can still reach INSERT afterwards.
-- Take the same per-owner lock as the purge, then reject that delayed reservation.
CREATE FUNCTION media_guard_purged_owner() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('media-quota:' || NEW.owner_id::text, 0));
    IF EXISTS (SELECT 1 FROM public.media_purged_owners WHERE owner_id = NEW.owner_id) THEN
        RAISE EXCEPTION 'media owner purged' USING ERRCODE = '23514', CONSTRAINT = 'media_owner_purged';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION media_guard_purged_owner() FROM PUBLIC;

CREATE TRIGGER media_guard_owner_before_insert BEFORE INSERT ON media_assets
    FOR EACH ROW EXECUTE FUNCTION media_guard_purged_owner();

CREATE FUNCTION media_purge_owner_batch(target UUID) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    finished UUID[];
BEGIN
    IF target IS NULL OR target = '00000000-0000-0000-0000-000000000000' THEN
        RAISE EXCEPTION 'invalid owner';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended('media-quota:' || target::text, 0));
    INSERT INTO public.media_purged_owners(owner_id) VALUES (target) ON CONFLICT DO NOTHING;

    UPDATE public.media_assets SET state = 'deleting', lease_until = NULL, lease_token = NULL
    WHERE id IN (
        SELECT id FROM public.media_assets WHERE owner_id = target AND state <> 'deleting'
        ORDER BY id LIMIT 100 FOR UPDATE
    );

    SELECT ARRAY(SELECT id FROM public.media_assets
        WHERE owner_id = target AND files_removed_at IS NOT NULL ORDER BY id LIMIT 100 FOR UPDATE)
    INTO finished;

    DELETE FROM public.media_ready_events WHERE asset_id = ANY(finished);
    DELETE FROM public.media_variants WHERE asset_id = ANY(finished);
    DELETE FROM public.media_uploads WHERE asset_id = ANY(finished);
    DELETE FROM public.media_assets WHERE id = ANY(finished);
    RETURN NOT EXISTS (SELECT 1 FROM public.media_assets WHERE owner_id = target);
END;
$$;
REVOKE ALL ON FUNCTION media_purge_owner_batch(UUID) FROM PUBLIC;
