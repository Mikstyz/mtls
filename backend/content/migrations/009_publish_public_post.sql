CREATE OR REPLACE FUNCTION content_guard_draft_edit() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.revision <> OLD.revision + 1 THEN
        RAISE EXCEPTION 'invalid post revision';
    END IF;

    IF OLD.status = 'draft' AND OLD.visibility = 'private'
        AND NEW.status = 'draft' AND NEW.visibility = 'private'
        AND NEW.published_at IS NOT DISTINCT FROM OLD.published_at THEN
        RETURN NEW;
    END IF;

    IF NEW.title IS DISTINCT FROM OLD.title OR NEW.description IS DISTINCT FROM OLD.description THEN
        RAISE EXCEPTION 'invalid post state change';
    END IF;

    IF OLD.status = 'draft' AND OLD.visibility = 'private'
        AND NEW.status = 'published' AND NEW.visibility IN ('private', 'public') THEN
        RETURN NEW;
    END IF;

    IF OLD.status IN ('draft', 'published') AND NEW.status = 'removed'
        AND NEW.author_removed_at IS NOT NULL AND NEW.visibility = OLD.visibility
        AND NEW.published_at IS NOT DISTINCT FROM OLD.published_at THEN
        RETURN NEW;
    END IF;

    IF OLD.status = 'removed' AND OLD.author_removed_at IS NOT NULL
        AND NEW.status = 'draft' AND NEW.visibility = 'private'
        AND NEW.author_removed_at IS NULL AND NEW.published_at IS NULL THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'invalid post state change';
END;
$$;

CREATE FUNCTION content_publish_post(
    draft_author UUID, draft_id UUID, expected_revision BIGINT, target_visibility TEXT
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

    IF current_post.status = 'published' AND current_post.revision = expected_revision + 1
        AND current_post.visibility = target_visibility THEN
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
        published_at = clock_timestamp(), revision = revision + 1
        WHERE id = draft_id RETURNING revision INTO current_post.revision;
    RETURN current_post.revision;
END;
$$;

REVOKE ALL ON FUNCTION content_publish_post(UUID, UUID, BIGINT, TEXT) FROM PUBLIC;

CREATE OR REPLACE FUNCTION content_publish_private(
    draft_author UUID, draft_id UUID, expected_revision BIGINT
) RETURNS BIGINT
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
    SELECT public.content_publish_post(draft_author, draft_id, expected_revision, 'private');
$$;
