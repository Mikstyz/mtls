CREATE TABLE content_video_covers (
    post_id UUID PRIMARY KEY REFERENCES content_posts(id) ON DELETE CASCADE,
    media_id UUID NOT NULL CHECK (media_id <> '00000000-0000-0000-0000-000000000000')
);

CREATE FUNCTION content_set_video_cover(owner UUID,target UUID,expected BIGINT,photo UUID)
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

    IF photo IS NULL THEN
        DELETE FROM public.content_video_covers WHERE post_id=target;
    ELSE
        INSERT INTO public.content_video_covers(post_id,media_id) VALUES(target,photo)
        ON CONFLICT(post_id) DO UPDATE SET media_id=EXCLUDED.media_id;
    END IF;
    RETURN current_revision;
END;
$$;
REVOKE ALL ON FUNCTION content_set_video_cover(UUID,UUID,BIGINT,UUID) FROM PUBLIC;
