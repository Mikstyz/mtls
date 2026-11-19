ALTER TABLE content_posts ADD COLUMN author_removed_at TIMESTAMPTZ;
ALTER TABLE content_posts ADD CONSTRAINT content_author_removed_status
    CHECK (author_removed_at IS NULL OR status = 'removed');

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
        AND NEW.status = 'published' AND NEW.visibility = 'private' THEN
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

CREATE FUNCTION content_change_author_removal(
    post_author UUID, post_id UUID, expected_revision BIGINT, restore BOOLEAN
) RETURNS BIGINT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    current_post public.content_posts%ROWTYPE;
BEGIN
    IF expected_revision IS NULL OR expected_revision NOT BETWEEN 1 AND 9223372036854775806
        OR restore IS NULL THEN
        RAISE EXCEPTION 'invalid post revision' USING ERRCODE = '22023';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || post_author::text, 0));
    SELECT * INTO current_post FROM public.content_posts
    WHERE id = post_id AND author_id = post_author
        AND NOT EXISTS (SELECT 1 FROM public.content_author_purges WHERE author_id = post_author)
    FOR UPDATE;

    IF NOT FOUND OR (current_post.status = 'removed' AND current_post.author_removed_at IS NULL) THEN
        RETURN -1;
    END IF;

    IF current_post.revision = expected_revision + 1 THEN
        IF NOT restore AND current_post.status = 'removed' THEN
            RETURN current_post.revision;
        END IF;
        RETURN 0;
    END IF;

    IF current_post.revision <> expected_revision THEN RETURN 0; END IF;

    IF restore AND current_post.status = 'removed' THEN
        UPDATE public.content_posts SET status = 'draft', visibility = 'private',
            author_removed_at = NULL, published_at = NULL, revision = revision + 1
            WHERE id = post_id RETURNING revision INTO current_post.revision;
    ELSIF NOT restore AND current_post.status IN ('draft', 'published') THEN
        UPDATE public.content_posts SET status = 'removed', author_removed_at = clock_timestamp(),
            revision = revision + 1 WHERE id = post_id RETURNING revision INTO current_post.revision;
    ELSE
        RETURN 0;
    END IF;

    RETURN current_post.revision;
END;
$$;

REVOKE ALL ON FUNCTION content_change_author_removal(UUID, UUID, BIGINT, BOOLEAN) FROM PUBLIC;
