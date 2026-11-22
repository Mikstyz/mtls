ALTER TABLE media_uploads ADD COLUMN transfer_mode TEXT CHECK (transfer_mode IN ('whole','resumable'));

UPDATE media_uploads SET transfer_mode='whole' WHERE uploaded;

CREATE FUNCTION media_begin_upload(owner UUID, asset UUID, total BIGINT, digest BYTEA, mode TEXT)
RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    current_mode TEXT;
BEGIN
    IF mode IS NULL OR mode NOT IN ('whole','resumable') THEN RETURN FALSE; END IF;

    PERFORM 1 FROM public.media_assets
    WHERE id=asset AND owner_id=owner AND state='reserved' FOR UPDATE;
    IF NOT FOUND THEN RETURN FALSE; END IF;

    SELECT transfer_mode INTO current_mode FROM public.media_uploads
    WHERE asset_id=asset AND byte_size=total AND sha256=digest AND NOT uploaded;
    IF NOT FOUND THEN RETURN FALSE; END IF;
    IF current_mode IS NOT NULL THEN RETURN current_mode=mode; END IF;

    UPDATE public.media_uploads SET transfer_mode=mode WHERE asset_id=asset;
    RETURN FOUND;
END;
$$;
REVOKE ALL ON FUNCTION media_begin_upload(UUID,UUID,BIGINT,BYTEA,TEXT) FROM PUBLIC;
