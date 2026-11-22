ALTER TABLE content_video_covers ADD COLUMN frame_name TEXT
    CHECK (frame_name IN ('poster-25.jpg','poster-60.jpg'));

CREATE FUNCTION content_set_video_cover(owner UUID,target UUID,expected BIGINT,photo UUID, frame TEXT)
RETURNS BIGINT LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    current_revision BIGINT;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || owner::text,0));
    SELECT revision INTO current_revision FROM public.content_posts
    WHERE id=target AND author_id=owner AND media_kind='video' AND status IN ('draft','published')
        AND NOT EXISTS(SELECT 1 FROM public.content_author_purges WHERE author_id=owner)
    FOR UPDATE;
    IF NOT FOUND THEN RETURN -1; END IF;
    IF current_revision<>expected THEN RETURN 0; END IF;

    IF frame IS NOT NULL AND (
        frame NOT IN ('poster-25.jpg','poster-60.jpg') OR photo IS NULL OR photo IS DISTINCT FROM
            (SELECT media_id FROM public.content_post_media WHERE post_id=target ORDER BY position LIMIT 1)
    ) THEN RETURN 0; END IF;

    IF photo IS NULL THEN
        DELETE FROM public.content_video_covers WHERE post_id=target;
    ELSE
        INSERT INTO public.content_video_covers(post_id,media_id,frame_name) VALUES(target,photo,frame)
        ON CONFLICT(post_id) DO UPDATE SET media_id=EXCLUDED.media_id,frame_name=EXCLUDED.frame_name;
    END IF;
    RETURN current_revision;
END;
$$;
REVOKE ALL ON FUNCTION content_set_video_cover(UUID,UUID,BIGINT,UUID,TEXT) FROM PUBLIC;

CREATE OR REPLACE FUNCTION content_set_video_cover(owner UUID,target UUID,expected BIGINT,photo UUID)
RETURNS BIGINT LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT public.content_set_video_cover(owner,target,expected,photo,NULL::TEXT)
$$;
