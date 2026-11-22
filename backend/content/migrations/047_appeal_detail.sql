CREATE FUNCTION content_appeal_detail(actor UUID, target UUID) RETURNS JSONB
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT jsonb_build_object(
        'case_id',r.case_id,'post_id',r.post_id,'comment_id',r.comment_id,
        'statement',a.statement,'submitted_at',a.submitted_at,
        'decision',decision.action,'rule',decision.rule,'severity',decision.severity,
        'decided_at',decision.occurred_at,
        'evidence',CASE
            WHEN r.comment_id IS NULL AND p.status='published' AND p.published_at<=r.created_at THEN
                jsonb_build_object('title',p.title,'description',p.description,'hidden',p.hidden_by_case IS NOT NULL)
            WHEN r.comment_id IS NOT NULL AND c.body IS NOT NULL THEN
                jsonb_build_object('body',c.body,'hidden',c.hidden_by_case IS NOT NULL)
        END
    )
    FROM public.content_moderation_appeals a
    JOIN public.content_reports r ON r.case_id=a.case_id
    JOIN public.content_posts p ON p.id=r.post_id
    LEFT JOIN public.content_comments c ON c.id=r.comment_id
    JOIN LATERAL (
        SELECT e.action,e.rule,e.severity,e.occurred_at
        FROM public.content_moderation_events e
        WHERE e.case_id=r.case_id AND e.action IN ('confirm','remove')
        ORDER BY e.revision DESC LIMIT 1
    ) decision ON TRUE
    WHERE r.case_id=target AND r.status='resolved' AND a.outcome IS NULL
        AND r.reporter_id IS DISTINCT FROM actor AND p.author_id<>actor
        AND (c.author_id IS NULL OR c.author_id<>actor)
        AND NOT EXISTS (
            SELECT 1 FROM public.content_moderation_events e WHERE e.case_id=r.case_id AND e.actor_id=actor
        )
        AND NOT EXISTS (
            SELECT 1 FROM public.content_author_purges WHERE author_id IN (actor,p.author_id,c.author_id)
        )
$$;

REVOKE ALL ON FUNCTION content_appeal_detail(UUID,UUID) FROM PUBLIC;

CREATE OR REPLACE FUNCTION content_appeal_queue(actor UUID)
RETURNS TABLE(case_id UUID,post_id UUID,comment_id UUID,statement TEXT,submitted_at TIMESTAMPTZ)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT a.case_id,c.post_id,c.comment_id,a.statement,a.submitted_at
    FROM public.content_moderation_appeals a JOIN public.content_case_owners c USING(case_id)
    JOIN public.content_posts p ON p.id=c.post_id
    WHERE a.outcome IS NULL AND c.status='resolved' AND p.author_id<>actor AND c.owner_id<>actor AND c.reporter_id IS DISTINCT FROM actor
      AND NOT EXISTS (SELECT 1 FROM public.content_moderation_events e
         WHERE e.case_id=a.case_id AND e.actor_id=actor)
      AND NOT EXISTS (SELECT 1 FROM public.content_author_purges WHERE author_id IN (actor,c.owner_id,p.author_id))
    ORDER BY a.submitted_at,a.case_id LIMIT 50
$$;

CREATE OR REPLACE FUNCTION content_review_appeal(actor UUID,target UUID,result TEXT) RETURNS INTEGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    item public.content_reports%ROWTYPE;
    previous public.content_moderation_appeals%ROWTYPE;
BEGIN
    IF result IS NULL OR result NOT IN ('upheld','reversed') THEN RETURN 409; END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || actor::text,0));
    SELECT r.* INTO item FROM public.content_reports r JOIN public.content_case_owners c USING(case_id)
    JOIN public.content_posts p ON p.id=r.post_id
    WHERE r.case_id=target AND p.author_id<>actor AND r.status='resolved' AND c.owner_id<>actor
        AND c.reporter_id IS DISTINCT FROM actor
        AND NOT EXISTS(SELECT 1 FROM public.content_moderation_events e WHERE e.case_id=target AND e.actor_id=actor)
        AND NOT EXISTS(SELECT 1 FROM public.content_author_purges WHERE author_id IN (actor,c.owner_id,p.author_id))
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
