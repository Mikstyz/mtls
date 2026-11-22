CREATE FUNCTION media_upload_cover_frames(owner UUID, asset UUID) RETURNS TEXT[]
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT ARRAY(
        SELECT v.name
        FROM public.media_assets a
        JOIN public.media_variants v ON v.asset_id=a.id
        WHERE a.id=asset AND a.owner_id=owner AND a.kind='video' AND a.state='processed'
            AND v.name IN ('poster-25.jpg','poster-60.jpg')
        ORDER BY v.name
    )
$$;

REVOKE ALL ON FUNCTION media_upload_cover_frames(UUID,UUID) FROM PUBLIC;
