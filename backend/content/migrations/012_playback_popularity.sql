CREATE INDEX content_post_view_receipts_popularity_idx
    ON content_post_view_receipts (post_id, view_day);

-- Each receipt represents one distinct viewer of the post.
CREATE FUNCTION content_popular_for_playback(target UUID) RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT EXISTS (
        SELECT 1 FROM public.content_post_view_receipts
        WHERE post_id = target AND view_day = (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')::date - DATE '1970-01-01'
        LIMIT 1 OFFSET 99
    )
$$;

REVOKE ALL ON FUNCTION content_popular_for_playback(UUID) FROM PUBLIC;
