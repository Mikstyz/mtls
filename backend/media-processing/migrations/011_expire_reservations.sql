CREATE INDEX media_reserved_by_age_idx ON media_assets (created_at,id)
    WHERE state='reserved';

CREATE FUNCTION media_expire_reservations(max_age_seconds INTEGER) RETURNS INTEGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    candidates UUID[];
    expired INTEGER;
BEGIN
    IF max_age_seconds IS NULL OR max_age_seconds NOT BETWEEN 3600 AND 2592000 THEN
        RAISE EXCEPTION 'invalid upload reservation lifetime';
    END IF;

    SELECT ARRAY(
        SELECT a.id FROM public.media_assets a JOIN public.media_uploads u ON a.id=u.asset_id
        WHERE a.state='reserved' AND NOT u.uploaded
            AND a.created_at <= clock_timestamp() - max_age_seconds * INTERVAL '1 second'
        ORDER BY a.created_at,a.id LIMIT 100 FOR UPDATE OF a SKIP LOCKED
    ) INTO candidates;

    -- Upload completion takes the asset lock before marking its bytes durable.
    -- Recheck uploaded with a fresh snapshot after acquiring that same lock.
    UPDATE public.media_assets a SET state='deleting'
    FROM public.media_uploads u
    WHERE a.id=ANY(candidates) AND a.id=u.asset_id AND a.state='reserved' AND NOT u.uploaded;
    GET DIAGNOSTICS expired = ROW_COUNT;
    RETURN expired;
END;
$$;
REVOKE ALL ON FUNCTION media_expire_reservations(INTEGER) FROM PUBLIC;
