CREATE FUNCTION content_moderation_case_detail(actor UUID, target UUID) RETURNS JSONB
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT jsonb_build_object(
        'case_id', r.case_id, 'post_id', r.post_id, 'comment_id', r.comment_id,
        'reason', r.reason, 'status', r.status, 'revision', r.revision,
        'escalated', r.escalated, 'created_at', r.created_at, 'assigned_until', r.assigned_until,
        'evidence', CASE WHEN r.status='reviewing' THEN
            CASE WHEN r.comment_id IS NULL THEN
                jsonb_build_object('title',p.title,'description',p.description,'hidden',p.hidden_by_case IS NOT NULL)
            ELSE
                jsonb_build_object('body',c.body,'hidden',c.hidden_by_case IS NOT NULL)
            END
        END,
        'events', COALESCE((
            SELECT jsonb_agg(to_jsonb(e) ORDER BY e.revision DESC)
            FROM (
                SELECT revision,actor_id,action,rule,severity,occurred_at
                FROM public.content_moderation_events
                WHERE case_id=r.case_id
                ORDER BY revision DESC LIMIT 50
            ) e
        ), '[]'::jsonb)
    )
    FROM public.content_reports r
    JOIN public.content_posts p ON p.id=r.post_id
    LEFT JOIN public.content_comments c ON c.id=r.comment_id
    WHERE r.case_id=target AND r.assigned_to=actor
        AND (r.status IN ('resolved','dismissed') OR
            (r.status='reviewing' AND r.assigned_until>statement_timestamp()))
        AND r.reporter_id IS DISTINCT FROM actor AND p.author_id<>actor
        AND (c.author_id IS NULL OR c.author_id<>actor)
        AND NOT EXISTS (
            SELECT 1 FROM public.content_author_purges q
            WHERE q.author_id IN (r.reporter_id,p.author_id,c.author_id,actor)
        )
$$;

REVOKE ALL ON FUNCTION content_moderation_case_detail(UUID,UUID) FROM PUBLIC;
