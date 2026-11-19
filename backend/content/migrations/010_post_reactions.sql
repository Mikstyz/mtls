CREATE TABLE content_post_likes (
    post_id UUID NOT NULL REFERENCES content_posts (id) ON DELETE CASCADE,
    viewer_id UUID NOT NULL,
    PRIMARY KEY (post_id, viewer_id)
);

CREATE INDEX content_post_likes_viewer_idx ON content_post_likes (viewer_id, post_id);

CREATE TABLE content_post_favorites (
    post_id UUID NOT NULL REFERENCES content_posts (id) ON DELETE CASCADE,
    viewer_id UUID NOT NULL,
    added_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (post_id, viewer_id)
);

CREATE INDEX content_post_favorites_viewer_idx
    ON content_post_favorites (viewer_id, added_at DESC, post_id DESC);

CREATE INDEX content_post_favorites_purge_idx ON content_post_favorites (viewer_id, post_id);

CREATE TABLE content_post_statistics (
    post_id UUID PRIMARY KEY REFERENCES content_posts (id) ON DELETE CASCADE,
    likes BIGINT NOT NULL DEFAULT 0 CHECK (likes >= 0)
);

CREATE FUNCTION content_set_reaction(
    reaction_post UUID, reaction_author UUID, reaction_viewer UUID, reaction_kind TEXT, enabled BOOLEAN
) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    IF reaction_kind IS NULL OR reaction_kind NOT IN ('like', 'favorite') OR enabled IS NULL
        OR reaction_post IS NULL OR reaction_author IS NULL OR reaction_viewer IS NULL
        OR '00000000-0000-0000-0000-000000000000'::UUID IN (reaction_post, reaction_author, reaction_viewer) THEN
        RAISE EXCEPTION 'invalid reaction' USING ERRCODE = '22023';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || reaction_viewer::text, 0));
    PERFORM 1 FROM public.content_posts AS p
    WHERE p.id = reaction_post AND p.author_id = reaction_author AND p.status = 'published'
        AND (p.visibility = 'public' OR p.author_id = reaction_viewer)
        AND NOT EXISTS (
            SELECT 1 FROM public.content_author_purges a
            WHERE a.author_id IN (reaction_viewer, reaction_author)
        )
    FOR SHARE;

    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    IF reaction_kind = 'like' THEN
        IF enabled THEN
            INSERT INTO public.content_post_likes (post_id, viewer_id)
                VALUES (reaction_post, reaction_viewer) ON CONFLICT DO NOTHING;
            IF FOUND THEN
                INSERT INTO public.content_post_statistics (post_id, likes) VALUES (reaction_post, 1)
                ON CONFLICT (post_id) DO UPDATE SET likes = public.content_post_statistics.likes + 1;
            END IF;
        ELSE
            DELETE FROM public.content_post_likes WHERE post_id = reaction_post AND viewer_id = reaction_viewer;
            IF FOUND THEN
                UPDATE public.content_post_statistics SET likes = likes - 1 WHERE post_id = reaction_post;
                IF NOT FOUND THEN RAISE EXCEPTION 'missing post statistics'; END IF;
            END IF;
        END IF;
    ELSIF enabled THEN
        INSERT INTO public.content_post_favorites (post_id, viewer_id)
            VALUES (reaction_post, reaction_viewer) ON CONFLICT DO NOTHING;
    ELSE
        DELETE FROM public.content_post_favorites WHERE post_id = reaction_post AND viewer_id = reaction_viewer;
    END IF;

    RETURN TRUE;
END;
$$;

CREATE FUNCTION content_purge_viewer_reactions(purge_viewer UUID) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    removed_post UUID;
    batch_posts UUID[];
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || purge_viewer::text, 0));
    IF NOT EXISTS (SELECT 1 FROM public.content_author_purges WHERE author_id = purge_viewer) THEN
        RAISE EXCEPTION 'missing content purge marker';
    END IF;

    -- Lock counters in post order. The caller commits this phase before locking
    -- and deleting any of the account's own posts.
    SELECT ARRAY(
        SELECT p.id FROM public.content_post_likes l
        JOIN public.content_posts p ON p.id = l.post_id
        WHERE l.viewer_id = purge_viewer ORDER BY p.id LIMIT 500 FOR SHARE OF p
    ) INTO batch_posts;

    IF cardinality(batch_posts) > 0 THEN
        FOR removed_post IN
            WITH removed AS (
                DELETE FROM public.content_post_likes l
                WHERE l.viewer_id = purge_viewer AND l.post_id = ANY(batch_posts)
                RETURNING l.post_id
            )
            SELECT post_id FROM removed ORDER BY post_id
        LOOP
            UPDATE public.content_post_statistics SET likes = likes - 1 WHERE post_id = removed_post;
            IF NOT FOUND THEN RAISE EXCEPTION 'missing post statistics'; END IF;
        END LOOP;
        RETURN TRUE;
    END IF;

    SELECT ARRAY(
        SELECT p.id FROM public.content_post_favorites f
        JOIN public.content_posts p ON p.id = f.post_id
        WHERE f.viewer_id = purge_viewer ORDER BY p.id LIMIT 500 FOR SHARE OF p
    ) INTO batch_posts;

    DELETE FROM public.content_post_favorites
    WHERE viewer_id = purge_viewer AND post_id = ANY(batch_posts);

    RETURN FOUND;
END;
$$;

REVOKE ALL ON FUNCTION content_set_reaction(UUID, UUID, UUID, TEXT, BOOLEAN) FROM PUBLIC;
REVOKE ALL ON FUNCTION content_purge_viewer_reactions(UUID) FROM PUBLIC;
