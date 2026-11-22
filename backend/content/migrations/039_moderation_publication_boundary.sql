CREATE OR REPLACE FUNCTION content_set_moderation_hide(item public.content_reports, hidden BOOLEAN)
RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
    IF item.comment_id IS NULL THEN
        IF hidden THEN
            UPDATE public.content_posts SET hidden_by_case=item.case_id
            WHERE id=item.post_id AND status='published' AND hidden_by_case IS NULL
                AND published_at<=item.created_at;
        ELSE
            UPDATE public.content_posts SET hidden_by_case=NULL
            WHERE id=item.post_id AND hidden_by_case=item.case_id;
        END IF;
    ELSIF hidden THEN
        UPDATE public.content_comments SET hidden_by_case=item.case_id
        WHERE id=item.comment_id AND post_id=item.post_id AND body IS NOT NULL AND hidden_by_case IS NULL;
    ELSE
        UPDATE public.content_comments SET hidden_by_case=NULL
        WHERE id=item.comment_id AND post_id=item.post_id AND hidden_by_case=item.case_id;
    END IF;
    RETURN FOUND;
END;
$$;

CREATE OR REPLACE FUNCTION content_moderation_case_detail(actor UUID, target UUID, before_revision BIGINT) RETURNS JSONB
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT jsonb_build_object(
        'case_id', r.case_id, 'post_id', r.post_id, 'comment_id', r.comment_id,
        'reason', r.reason, 'status', r.status, 'revision', r.revision,
        'escalated', r.escalated, 'created_at', r.created_at, 'assigned_until', r.assigned_until,
        'evidence', CASE WHEN r.status='reviewing' THEN
            CASE
            WHEN r.comment_id IS NULL AND p.status='published' AND p.published_at<=r.created_at THEN
                jsonb_build_object('title',p.title,'description',p.description,'hidden',p.hidden_by_case IS NOT NULL)
            WHEN r.comment_id IS NOT NULL THEN
                jsonb_build_object('body',c.body,'hidden',c.hidden_by_case IS NOT NULL)
            END
        END,
        'media_ids', CASE WHEN r.status='reviewing' AND r.comment_id IS NULL THEN COALESCE((
            SELECT jsonb_agg(m.media_id ORDER BY m.position)
            FROM public.content_reviewable_post(actor,target) review
            JOIN public.content_post_media m ON m.post_id=review.post_id
        ), '[]'::jsonb) END,
        'events', COALESCE(history.events, '[]'::jsonb),
        'next_before_revision', history.next_before_revision
    )
    FROM public.content_reports r
    JOIN public.content_posts p ON p.id=r.post_id
    LEFT JOIN public.content_comments c ON c.id=r.comment_id
    CROSS JOIN LATERAL (
        SELECT jsonb_agg(to_jsonb(e) - 'position' ORDER BY e.revision DESC)
                   FILTER (WHERE e.position <= 50) AS events,
               CASE WHEN count(*) > 50 THEN min(e.revision)
                   FILTER (WHERE e.position <= 50) END AS next_before_revision
        FROM (
            SELECT revision,actor_id,action,rule,severity,occurred_at,
                   row_number() OVER (ORDER BY revision DESC) AS position
            FROM public.content_moderation_events
            WHERE case_id=r.case_id AND (before_revision IS NULL OR revision<before_revision)
            ORDER BY revision DESC LIMIT 51
        ) e
    ) history
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
