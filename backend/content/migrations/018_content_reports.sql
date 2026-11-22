CREATE TABLE content_reports (
    reporter_id UUID NOT NULL,
    id UUID NOT NULL,
    post_id UUID NOT NULL REFERENCES content_posts(id) ON DELETE CASCADE,
    comment_id UUID REFERENCES content_comments(id) ON DELETE CASCADE,
    reason TEXT NOT NULL CHECK (reason IN ('spam','harassment','consent','age_safety','other')),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','reviewing','resolved','dismissed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (reporter_id,id)
);

CREATE UNIQUE INDEX content_report_post_once ON content_reports(reporter_id,post_id)
    WHERE comment_id IS NULL;
CREATE UNIQUE INDEX content_report_comment_once ON content_reports(reporter_id,comment_id)
    WHERE comment_id IS NOT NULL;
CREATE INDEX content_report_reporter_recent ON content_reports(reporter_id,created_at DESC);
CREATE INDEX content_report_queue ON content_reports(created_at,reporter_id,id)
    WHERE status='pending';

CREATE FUNCTION content_submit_report(viewer UUID, request UUID, target UUID, comment UUID, category TEXT,
    allow_test BOOLEAN) RETURNS TEXT
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    previous public.content_reports%ROWTYPE;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || viewer::text,0));
    IF EXISTS(SELECT 1 FROM public.content_author_purges WHERE author_id=viewer) THEN
        RETURN 'missing';
    END IF;

    SELECT * INTO previous FROM public.content_reports WHERE reporter_id=viewer AND id=request;
    IF FOUND THEN
        IF previous.post_id=target AND previous.comment_id IS NOT DISTINCT FROM comment
            AND previous.reason=category THEN RETURN 'replay'; END IF;
        RETURN 'conflict';
    END IF;

    PERFORM 1 FROM public.content_posts p WHERE p.id=target AND p.status='published'
        AND (p.visibility='public' OR p.author_id=viewer
            OR (p.visibility='private' AND allow_test
                AND has_function_privilege(session_user,'public.content_test_purchase(uuid,uuid,uuid,bigint)','EXECUTE')
                AND public.content_test_entitled(p.id,p.revision,viewer)))
        AND NOT EXISTS (SELECT 1 FROM public.content_author_purges WHERE author_id=p.author_id)
        FOR SHARE;
    IF NOT FOUND THEN RETURN 'missing'; END IF;

    IF comment IS NOT NULL THEN
        PERFORM 1 FROM public.content_comments c
        WHERE c.id=comment AND c.post_id=target AND c.body IS NOT NULL
            AND NOT EXISTS (SELECT 1 FROM public.content_author_purges WHERE author_id=c.author_id)
            FOR SHARE;
        IF NOT FOUND THEN RETURN 'missing'; END IF;
    END IF;

    IF EXISTS (SELECT 1 FROM public.content_reports WHERE reporter_id=viewer
        AND post_id=target AND comment_id IS NOT DISTINCT FROM comment) THEN RETURN 'conflict'; END IF;
    IF EXISTS (SELECT 1 FROM public.content_reports WHERE reporter_id=viewer
        AND created_at>clock_timestamp()-INTERVAL '1 hour' LIMIT 1 OFFSET 4) THEN RETURN 'limited'; END IF;

    INSERT INTO public.content_reports(reporter_id,id,post_id,comment_id,reason)
        VALUES(viewer,request,target,comment,category);
    RETURN 'created';
END;
$$;

CREATE FUNCTION content_own_report(viewer UUID, request UUID)
RETURNS TABLE(id UUID,post_id UUID,comment_id UUID,reason TEXT,status TEXT,created_at TIMESTAMPTZ)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT r.id,r.post_id,r.comment_id,r.reason,r.status,r.created_at
    FROM public.content_reports r WHERE r.reporter_id=viewer AND r.id=request
        AND NOT EXISTS(SELECT 1 FROM public.content_author_purges WHERE author_id=viewer)
$$;

CREATE FUNCTION content_purge_reporter(viewer UUID) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
    IF NOT EXISTS(SELECT 1 FROM public.content_author_purges WHERE author_id=viewer) THEN
        RAISE EXCEPTION 'missing reporter purge marker';
    END IF;
    DELETE FROM public.content_reports WHERE reporter_id=viewer AND id IN (
        SELECT id FROM public.content_reports WHERE reporter_id=viewer ORDER BY id LIMIT 500
    );
    RETURN FOUND;
END;
$$;

REVOKE ALL ON FUNCTION content_submit_report(UUID,UUID,UUID,UUID,TEXT,BOOLEAN),
    content_own_report(UUID,UUID),content_purge_reporter(UUID) FROM PUBLIC;
