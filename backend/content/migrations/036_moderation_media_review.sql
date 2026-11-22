CREATE FUNCTION content_reviewable_post(actor UUID, target UUID)
RETURNS TABLE(post_id UUID, author_id UUID)
LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $$
    SELECT p.id,p.author_id
    FROM public.content_reports r
    JOIN public.content_posts p ON p.id=r.post_id
    WHERE r.case_id=target AND r.comment_id IS NULL
        AND p.status='published' AND p.published_at<=r.created_at
        AND r.status='reviewing' AND r.assigned_to=actor AND r.assigned_until>statement_timestamp()
        AND r.reporter_id IS DISTINCT FROM actor AND p.author_id<>actor
        AND NOT EXISTS (
            SELECT 1 FROM public.content_author_purges q
            WHERE q.author_id IN (r.reporter_id,p.author_id,actor)
        )
$$;

CREATE FUNCTION content_case_media_access(actor UUID, target UUID, media UUID, owner UUID)
RETURNS BOOLEAN LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT EXISTS (
        SELECT 1 FROM public.content_reviewable_post(actor,target) p
        JOIN public.content_post_media m ON m.post_id=p.post_id
        WHERE p.author_id=owner AND m.media_id=media
    )
$$;

REVOKE ALL ON FUNCTION content_reviewable_post(UUID,UUID),
    content_case_media_access(UUID,UUID,UUID,UUID) FROM PUBLIC;

CREATE OR REPLACE FUNCTION content_moderation_case_detail(actor UUID, target UUID) RETURNS JSONB
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
        'media_ids', CASE WHEN r.status='reviewing' AND r.comment_id IS NULL THEN COALESCE((
            SELECT jsonb_agg(m.media_id ORDER BY m.position)
            FROM public.content_reviewable_post(actor,target) review
            JOIN public.content_post_media m ON m.post_id=review.post_id
        ), '[]'::jsonb) END,
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
