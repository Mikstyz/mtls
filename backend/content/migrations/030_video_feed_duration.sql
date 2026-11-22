ALTER TABLE content_posts ADD COLUMN video_duration_ms BIGINT
    CHECK(video_duration_ms IS NULL OR (media_kind='video' AND video_duration_ms BETWEEN 1 AND 86400000));

CREATE FUNCTION content_publish_post_duration(
    draft_author UUID, draft_id UUID, expected_revision BIGINT, target_visibility TEXT, duration BIGINT
) RETURNS BIGINT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    current_post public.content_posts%ROWTYPE;
BEGIN
    IF expected_revision IS NULL OR expected_revision NOT BETWEEN 1 AND 9223372036854775806
        OR target_visibility IS NULL OR target_visibility NOT IN ('private', 'public') THEN
        RAISE EXCEPTION 'invalid draft revision' USING ERRCODE = '22023';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || draft_author::text, 0));
    SELECT * INTO current_post FROM public.content_posts
    WHERE id = draft_id AND author_id = draft_author AND ((status = 'draft' AND visibility = 'private') OR status = 'published')
        AND NOT EXISTS (SELECT 1 FROM public.content_author_purges WHERE author_id = draft_author)
    FOR UPDATE;
    IF NOT FOUND THEN RETURN -1; END IF;
    IF duration IS NOT NULL AND (current_post.media_kind<>'video' OR duration NOT BETWEEN 1 AND 86400000) THEN RETURN -2; END IF;

    IF current_post.status = 'published' AND current_post.revision = expected_revision + 1
        AND current_post.visibility = target_visibility
        AND (duration IS NULL OR duration IS NOT DISTINCT FROM current_post.video_duration_ms) THEN
        RETURN current_post.revision;
    END IF;

    IF current_post.status <> 'draft' OR current_post.revision <> expected_revision THEN
        RETURN 0;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM public.content_post_media WHERE post_id = draft_id)
        OR btrim(current_post.title) = '' THEN
        RETURN -2;
    END IF;

    UPDATE public.content_posts SET status = 'published', visibility = target_visibility,
        published_at = clock_timestamp(), published_edition=NULL, video_duration_ms=duration, revision = revision + 1
        WHERE id = draft_id RETURNING revision INTO current_post.revision;
    RETURN current_post.revision;
END;
$$;

CREATE OR REPLACE FUNCTION content_publish_post(draft_author UUID,draft_id UUID,expected_revision BIGINT,target_visibility TEXT)
RETURNS BIGINT LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT public.content_publish_post_duration(draft_author,draft_id,expected_revision,target_visibility,NULL)
$$;

CREATE FUNCTION content_publish_scheduled_post(target UUID,job UUID,owner UUID,duration BIGINT) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    item public.content_scheduled_posts%ROWTYPE;
    changed BIGINT;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || owner::text,0));
    PERFORM 1 FROM public.content_posts WHERE id=target AND author_id=owner
        AND status='draft' AND hidden_by_case IS NULL FOR UPDATE;
    IF NOT FOUND THEN RETURN FALSE; END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('content-points:' || owner::text,0));
    IF EXISTS(SELECT 1 FROM public.content_active_points_ban(owner)) THEN RETURN FALSE; END IF;
    SELECT * INTO item FROM public.content_scheduled_posts
        WHERE schedule_id=job AND post_id=target AND publish_at<=clock_timestamp() FOR UPDATE;
    IF NOT FOUND THEN RETURN FALSE; END IF;

    SELECT public.content_publish_post_duration(owner,target,item.revision,item.visibility,duration) INTO changed;
    RETURN changed>0;
END;
$$;

CREATE OR REPLACE FUNCTION content_publish_scheduled_post(target UUID,job UUID,owner UUID)
RETURNS BOOLEAN LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT public.content_publish_scheduled_post(target,job,owner,NULL)
$$;

REVOKE ALL ON FUNCTION content_publish_post_duration(UUID,UUID,BIGINT,TEXT,BIGINT),
    content_publish_scheduled_post(UUID,UUID,UUID,BIGINT) FROM PUBLIC;

CREATE INDEX content_public_short_video_idx ON content_posts(published_at DESC,id DESC)
    WHERE status='published' AND visibility='public' AND hidden_by_case IS NULL
        AND media_kind='video' AND video_duration_ms<=60000;
CREATE INDEX content_public_long_video_idx ON content_posts(published_at DESC,id DESC)
    WHERE status='published' AND visibility='public' AND hidden_by_case IS NULL
        AND media_kind='video' AND video_duration_ms>60000;
