ALTER TABLE content_post_statistics ADD COLUMN views BIGINT NOT NULL DEFAULT 0 CHECK (views >= 0);

CREATE TABLE content_post_view_receipts (
    post_id UUID NOT NULL REFERENCES content_posts (id) ON DELETE CASCADE,
    viewer_id UUID NOT NULL,
    view_day INTEGER NOT NULL,
    PRIMARY KEY (post_id, viewer_id)
);

CREATE INDEX content_post_view_receipts_viewer_idx ON content_post_view_receipts (viewer_id, post_id);
CREATE INDEX content_post_view_receipts_expiry_idx ON content_post_view_receipts (view_day);

CREATE FUNCTION content_count_post_view(view_post UUID, view_media UUID, view_user UUID, observed_day INTEGER)
RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    today INTEGER := (clock_timestamp() AT TIME ZONE 'UTC')::DATE - DATE '1970-01-01';
BEGIN
    IF observed_day NOT BETWEEN today - 1 AND today THEN
        RETURN;
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || view_user::text, 0));
    PERFORM 1 FROM public.content_posts p
    JOIN public.content_post_media m ON m.post_id = p.id AND m.media_id = view_media
    WHERE p.id = view_post AND p.status = 'published' AND p.visibility = 'public'
        AND p.author_id <> view_user
        AND NOT EXISTS (
            SELECT 1 FROM public.content_author_purges a WHERE a.author_id IN (p.author_id, view_user)
        )
    FOR SHARE OF p;

    IF NOT FOUND THEN RETURN; END IF;

    INSERT INTO public.content_post_view_receipts (post_id, viewer_id, view_day)
        VALUES (view_post, view_user, observed_day)
    ON CONFLICT (post_id, viewer_id) DO UPDATE SET view_day = EXCLUDED.view_day
        WHERE public.content_post_view_receipts.view_day < EXCLUDED.view_day;

    IF FOUND THEN
        INSERT INTO public.content_post_statistics (post_id, views) VALUES (view_post, 1)
        ON CONFLICT (post_id) DO UPDATE SET views = public.content_post_statistics.views + 1;
    END IF;
END;
$$;

CREATE FUNCTION content_purge_view_receipts(purge_viewer UUID) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || purge_viewer::text, 0));
    IF NOT EXISTS (SELECT 1 FROM public.content_author_purges WHERE author_id = purge_viewer) THEN
        RAISE EXCEPTION 'missing content purge marker';
    END IF;

    DELETE FROM public.content_post_view_receipts r
    USING (
        SELECT p.id FROM public.content_post_view_receipts v
        JOIN public.content_posts p ON p.id = v.post_id
        WHERE v.viewer_id = purge_viewer ORDER BY p.id LIMIT 500 FOR SHARE OF p
    ) batch
    WHERE r.post_id = batch.id AND r.viewer_id = purge_viewer;

    RETURN FOUND;
END;
$$;

CREATE FUNCTION content_prune_view_receipts() RETURNS INTEGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    cutoff INTEGER := (clock_timestamp() AT TIME ZONE 'UTC')::DATE - DATE '1970-01-01' - 1;
    removed INTEGER;
BEGIN
    DELETE FROM public.content_post_view_receipts r
    USING (
        SELECT post_id, viewer_id FROM public.content_post_view_receipts
        WHERE view_day < cutoff ORDER BY view_day LIMIT 1000 FOR UPDATE SKIP LOCKED
    ) expired
    WHERE r.post_id = expired.post_id AND r.viewer_id = expired.viewer_id;

    GET DIAGNOSTICS removed = ROW_COUNT;
    RETURN removed;
END;
$$;

REVOKE ALL ON FUNCTION content_count_post_view(UUID, UUID, UUID, INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION content_purge_view_receipts(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION content_prune_view_receipts() FROM PUBLIC;
