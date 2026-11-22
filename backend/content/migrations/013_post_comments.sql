CREATE TABLE content_comments (
    id UUID PRIMARY KEY,
    post_id UUID NOT NULL REFERENCES content_posts(id) ON DELETE CASCADE,
    author_id UUID NOT NULL,
    body TEXT CHECK (char_length(body) BETWEEN 1 AND 2000 AND btrim(body) <> ''),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX content_comments_page_idx ON content_comments(post_id, created_at DESC, id DESC)
    WHERE body IS NOT NULL;
CREATE INDEX content_comments_author_idx ON content_comments(author_id, created_at DESC);

-- NULL input deletes the author's comment. A retained ID prevents resurrection by a retry.
CREATE FUNCTION content_write_comment(target UUID, actor UUID, comment_id UUID, message TEXT)
RETURNS INTEGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    previous public.content_comments%ROWTYPE;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || actor::text, 0));
    PERFORM 1 FROM public.content_posts p
    WHERE p.id=target AND p.status='published' AND (p.visibility='public' OR p.author_id=actor)
        AND NOT EXISTS (SELECT 1 FROM public.content_author_purges a WHERE a.author_id IN (actor,p.author_id))
    FOR SHARE;
    IF NOT FOUND THEN RETURN 404; END IF;

    SELECT * INTO previous FROM public.content_comments WHERE id=comment_id;
    IF FOUND THEN
        IF previous.author_id <> actor OR previous.post_id <> target THEN RETURN 404; END IF;
        IF message IS NULL THEN
            UPDATE public.content_comments SET body=NULL WHERE id=comment_id AND body IS NOT NULL;
            RETURN 204;
        END IF;
        IF previous.body IS DISTINCT FROM message THEN RETURN 409; END IF;
        RETURN 204;
    END IF;
    IF message IS NULL THEN RETURN 404; END IF;

    IF EXISTS (SELECT 1 FROM public.content_comments WHERE author_id=actor
        AND created_at > clock_timestamp() - INTERVAL '1 minute' OFFSET 4 LIMIT 1)
    THEN RETURN 429; END IF;

    INSERT INTO public.content_comments(id,post_id,author_id,body)
    VALUES(comment_id,target,actor,message) ON CONFLICT (id) DO NOTHING;
    IF NOT FOUND THEN RETURN 404; END IF;
    RETURN 201;
END;
$$;

CREATE FUNCTION content_purge_comments(actor UUID) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || actor::text, 0));
    IF NOT EXISTS (SELECT 1 FROM public.content_author_purges WHERE author_id=actor) THEN
        RAISE EXCEPTION 'missing author purge marker';
    END IF;
    DELETE FROM public.content_comments WHERE id IN (
        SELECT id FROM public.content_comments WHERE author_id=actor ORDER BY created_at,id LIMIT 500
    );
    RETURN FOUND;
END;
$$;

REVOKE ALL ON FUNCTION content_write_comment(UUID,UUID,UUID,TEXT), content_purge_comments(UUID) FROM PUBLIC;
