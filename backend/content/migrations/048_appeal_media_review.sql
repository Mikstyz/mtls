CREATE FUNCTION content_can_read_pending_appeal(actor UUID, target UUID) RETURNS BOOLEAN
LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $$
    SELECT EXISTS (
        SELECT 1
        FROM public.content_moderation_appeals a
        JOIN public.content_reports r ON r.case_id=a.case_id
        JOIN public.content_posts p ON p.id=r.post_id
        LEFT JOIN public.content_comments c ON c.id=r.comment_id
        WHERE r.case_id=target AND r.status='resolved' AND a.outcome IS NULL
            AND r.reporter_id IS DISTINCT FROM actor AND p.author_id<>actor
            AND (c.author_id IS NULL OR c.author_id<>actor)
            AND NOT EXISTS (
                SELECT 1 FROM public.content_moderation_events e WHERE e.case_id=r.case_id AND e.actor_id=actor
            )
            AND NOT EXISTS (
                SELECT 1 FROM public.content_author_purges WHERE author_id IN (actor,p.author_id,c.author_id)
            )
    )
$$;

REVOKE ALL ON FUNCTION content_can_read_pending_appeal(UUID,UUID) FROM PUBLIC;

CREATE OR REPLACE FUNCTION content_appeal_detail(actor UUID, target UUID) RETURNS JSONB
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT jsonb_build_object(
        'case_id',r.case_id,'post_id',r.post_id,'comment_id',r.comment_id,
        'statement',a.statement,'submitted_at',a.submitted_at,
        'decision',decision.action,'rule',decision.rule,'severity',decision.severity,
        'decided_at',decision.occurred_at,
        'media_ids', CASE
            WHEN r.comment_id IS NULL AND p.status='published' AND p.published_at<=r.created_at THEN
                COALESCE((SELECT jsonb_agg(m.media_id ORDER BY m.position)
                    FROM public.content_post_media m WHERE m.post_id=p.id), '[]'::jsonb)
        END,
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
    WHERE r.case_id=target AND public.content_can_read_pending_appeal(actor,target)
$$;

CREATE OR REPLACE FUNCTION content_case_media_access(actor UUID, target UUID, media UUID, owner UUID)
RETURNS BOOLEAN LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT EXISTS (
        SELECT 1 FROM public.content_reviewable_post(actor,target) p
        JOIN public.content_post_media m ON m.post_id=p.post_id
        WHERE p.author_id=owner AND m.media_id=media
    ) OR EXISTS (
        SELECT 1
        FROM public.content_reports r
        JOIN public.content_posts p ON p.id=r.post_id
        JOIN public.content_post_media m ON m.post_id=p.id
        WHERE r.case_id=target AND r.comment_id IS NULL
            AND p.author_id=owner AND m.media_id=media
            AND p.status='published' AND p.published_at<=r.created_at
            AND public.content_can_read_pending_appeal(actor,target)
    )
$$;
