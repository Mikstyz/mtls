CREATE OR REPLACE FUNCTION content_write_comment(target UUID, actor UUID, comment_id UUID, message TEXT, allow_test BOOLEAN)
RETURNS INTEGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    previous public.content_comments%ROWTYPE;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || actor::text, 0));
    IF message IS NULL THEN
        UPDATE public.content_comments SET body=NULL
        WHERE id=comment_id AND post_id=target AND author_id=actor
            AND NOT EXISTS (SELECT 1 FROM public.content_author_purges WHERE author_id=actor);
        IF NOT FOUND THEN RETURN 404; END IF;
        RETURN 204;
    END IF;

    PERFORM 1 FROM public.content_posts p
    WHERE p.id=target AND p.status='published' AND p.hidden_by_case IS NULL AND ((p.visibility='public' OR p.author_id=actor OR (p.visibility='private' AND allow_test AND public.content_test_entitled(p.id,p.revision,actor))))
        AND NOT EXISTS (SELECT 1 FROM public.content_author_purges a WHERE a.author_id IN (actor,p.author_id))
    FOR SHARE;
    IF NOT FOUND THEN RETURN 404; END IF;

    SELECT * INTO previous FROM public.content_comments WHERE id=comment_id;
    IF FOUND THEN
        IF previous.author_id <> actor OR previous.post_id <> target THEN RETURN 404; END IF;
        IF previous.body IS DISTINCT FROM message THEN RETURN 409; END IF;
        RETURN 204;
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended('content-points:' || actor::text,0));
    IF EXISTS (SELECT 1 FROM public.content_owner_points(actor) WHERE comments_limited) THEN RETURN 403; END IF;

    IF EXISTS (SELECT 1 FROM public.content_comments WHERE author_id=actor
        AND created_at > clock_timestamp() - INTERVAL '1 minute' OFFSET 4 LIMIT 1)
    THEN RETURN 429; END IF;

    INSERT INTO public.content_comments(id,post_id,author_id,body)
    VALUES(comment_id,target,actor,message) ON CONFLICT (id) DO NOTHING;
    IF NOT FOUND THEN RETURN 404; END IF;
    RETURN 201;
END;
$$;
