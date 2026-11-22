CREATE FUNCTION content_set_reaction(
    reaction_post UUID, reaction_author UUID, reaction_viewer UUID, reaction_kind TEXT, enabled BOOLEAN, allow_test BOOLEAN
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
        AND ((p.visibility = 'public' OR p.author_id = reaction_viewer OR (p.visibility='private' AND allow_test AND public.content_test_entitled(p.id,p.revision,reaction_viewer))))
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

CREATE OR REPLACE FUNCTION content_set_reaction(
    reaction_post UUID, reaction_author UUID, reaction_viewer UUID, reaction_kind TEXT, enabled BOOLEAN
) RETURNS BOOLEAN LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT public.content_set_reaction($1,$2,$3,$4,$5,FALSE)
$$;

REVOKE ALL ON FUNCTION content_set_reaction(UUID,UUID,UUID,TEXT,BOOLEAN,BOOLEAN) FROM PUBLIC;

CREATE FUNCTION content_write_comment(target UUID, actor UUID, comment_id UUID, message TEXT, allow_test BOOLEAN)
RETURNS INTEGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    previous public.content_comments%ROWTYPE;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || actor::text, 0));
    PERFORM 1 FROM public.content_posts p
    WHERE p.id=target AND p.status='published' AND ((p.visibility='public' OR p.author_id=actor OR (p.visibility='private' AND allow_test AND public.content_test_entitled(p.id,p.revision,actor))))
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

CREATE OR REPLACE FUNCTION content_write_comment(target UUID, actor UUID, comment_id UUID, message TEXT)
RETURNS INTEGER LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT public.content_write_comment($1,$2,$3,$4,FALSE)
$$;

REVOKE ALL ON FUNCTION content_write_comment(UUID,UUID,UUID,TEXT,BOOLEAN) FROM PUBLIC;

CREATE FUNCTION content_count_post_view(view_post UUID, view_media UUID, view_user UUID, observed_day INTEGER, allow_test BOOLEAN)
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
    WHERE p.id = view_post AND p.status = 'published' AND (p.visibility = 'public' OR (p.visibility='private' AND allow_test AND public.content_test_entitled(p.id,p.revision,view_user)))
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

CREATE OR REPLACE FUNCTION content_count_post_view(view_post UUID, view_media UUID, view_user UUID, observed_day INTEGER)
RETURNS VOID LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT public.content_count_post_view($1,$2,$3,$4,FALSE)
$$;

REVOKE ALL ON FUNCTION content_count_post_view(UUID,UUID,UUID,INTEGER,BOOLEAN) FROM PUBLIC;
