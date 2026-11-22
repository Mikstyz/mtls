CREATE VIEW content_case_owners AS
SELECT r.case_id,r.post_id,r.comment_id,r.reporter_id,r.status,r.reason,
    CASE WHEN r.comment_id IS NULL THEN p.author_id ELSE c.author_id END AS owner_id,
    CASE WHEN r.comment_id IS NULL THEN p.hidden_by_case ELSE c.hidden_by_case END AS hidden_by_case
FROM content_reports r JOIN content_posts p ON p.id=r.post_id
LEFT JOIN content_comments c ON c.id=r.comment_id;

CREATE TABLE content_moderation_appeals (
    case_id UUID PRIMARY KEY REFERENCES content_reports(case_id) ON DELETE CASCADE,
    statement TEXT NOT NULL CHECK (char_length(statement) BETWEEN 1 AND 1000),
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    outcome TEXT CHECK(outcome IN ('upheld','reversed')),
    reviewed_by UUID,
    reviewed_at TIMESTAMPTZ,
    CHECK ((outcome IS NULL AND reviewed_by IS NULL AND reviewed_at IS NULL)
        OR (outcome IS NOT NULL AND reviewed_by IS NOT NULL AND reviewed_at IS NOT NULL))
);
CREATE INDEX content_appeals_pending_idx ON content_moderation_appeals(submitted_at,case_id) WHERE outcome IS NULL;

CREATE FUNCTION content_owner_moderation(owner UUID)
RETURNS TABLE(case_id UUID,post_id UUID,comment_id UUID,status TEXT,rule TEXT,severity TEXT,
    hidden BOOLEAN,appeal TEXT,decision_at TIMESTAMPTZ)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT c.case_id,c.post_id,c.comment_id,c.status,COALESCE(e.rule,c.reason),e.severity,
      COALESCE(c.hidden_by_case=c.case_id,FALSE),
      CASE WHEN a.case_id IS NOT NULL THEN COALESCE(a.outcome,'pending') END,e.occurred_at
    FROM public.content_case_owners c
    JOIN LATERAL (
      SELECT rule,severity,occurred_at FROM public.content_moderation_events e
      WHERE e.case_id=c.case_id AND e.action IN ('hide','dismiss','confirm')
      ORDER BY revision DESC LIMIT 1
    ) e ON TRUE
    LEFT JOIN public.content_moderation_appeals a ON a.case_id=c.case_id
    WHERE c.owner_id=owner AND (c.status='resolved' OR a.case_id IS NOT NULL OR EXISTS(
        SELECT 1 FROM public.content_moderation_events h WHERE h.case_id=c.case_id AND h.action='hide'))
      AND NOT EXISTS(SELECT 1 FROM public.content_author_purges WHERE author_id=owner)
    ORDER BY e.occurred_at DESC,c.case_id
    LIMIT 50
$$;

CREATE FUNCTION content_submit_appeal(owner UUID,target UUID,explanation TEXT) RETURNS INTEGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    previous TEXT;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || owner::text,0));
    PERFORM 1 FROM public.content_reports r JOIN public.content_case_owners c USING(case_id)
    WHERE r.case_id=target AND c.owner_id=owner AND r.status='resolved'
      AND NOT EXISTS(SELECT 1 FROM public.content_author_purges WHERE author_id=owner)
    FOR UPDATE OF r;
    IF NOT FOUND THEN RETURN 404; END IF;

    SELECT statement INTO previous FROM public.content_moderation_appeals WHERE case_id=target;
    IF FOUND THEN
        IF previous=explanation THEN RETURN 204; END IF;
        RETURN 409;
    END IF;

    INSERT INTO public.content_moderation_appeals(case_id,statement) VALUES(target,explanation);
    RETURN 201;
END;
$$;

CREATE FUNCTION content_appeal_queue(actor UUID)
RETURNS TABLE(case_id UUID,post_id UUID,comment_id UUID,statement TEXT,submitted_at TIMESTAMPTZ)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT a.case_id,c.post_id,c.comment_id,a.statement,a.submitted_at
    FROM public.content_moderation_appeals a JOIN public.content_case_owners c USING(case_id)
    WHERE a.outcome IS NULL AND c.owner_id<>actor AND c.reporter_id IS DISTINCT FROM actor
      AND NOT EXISTS (SELECT 1 FROM public.content_moderation_events e
         WHERE e.case_id=a.case_id AND e.actor_id=actor)
      AND NOT EXISTS (SELECT 1 FROM public.content_author_purges WHERE author_id IN (actor,c.owner_id))
    ORDER BY a.submitted_at,a.case_id LIMIT 50
$$;

CREATE FUNCTION content_review_appeal(actor UUID,target UUID,result TEXT) RETURNS INTEGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    item public.content_reports%ROWTYPE;
    previous public.content_moderation_appeals%ROWTYPE;
BEGIN
    IF result IS NULL OR result NOT IN ('upheld','reversed') THEN RETURN 409; END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || actor::text,0));
    SELECT r.* INTO item FROM public.content_reports r JOIN public.content_case_owners c USING(case_id)
    WHERE r.case_id=target AND r.status='resolved' AND c.owner_id<>actor
        AND c.reporter_id IS DISTINCT FROM actor
        AND NOT EXISTS(SELECT 1 FROM public.content_moderation_events e WHERE e.case_id=target AND e.actor_id=actor)
        AND NOT EXISTS(SELECT 1 FROM public.content_author_purges WHERE author_id IN (actor,c.owner_id))
    FOR UPDATE OF r;
    IF NOT FOUND THEN RETURN 404; END IF;

    SELECT * INTO previous FROM public.content_moderation_appeals WHERE case_id=target FOR UPDATE;
    IF NOT FOUND THEN RETURN 404; END IF;
    IF previous.outcome IS NOT NULL THEN
        IF previous.outcome=result AND previous.reviewed_by=actor THEN RETURN 204; END IF;
        RETURN 409;
    END IF;

    IF result='reversed' THEN
        PERFORM public.content_set_moderation_hide(item,FALSE);
    END IF;

    UPDATE public.content_moderation_appeals SET outcome=result,reviewed_by=actor,reviewed_at=clock_timestamp()
      WHERE case_id=target;
    RETURN 204;
END;
$$;

REVOKE ALL ON FUNCTION content_owner_moderation(UUID),content_submit_appeal(UUID,UUID,TEXT),
    content_appeal_queue(UUID),content_review_appeal(UUID,UUID,TEXT) FROM PUBLIC;
