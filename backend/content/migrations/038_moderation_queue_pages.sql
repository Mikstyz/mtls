CREATE FUNCTION content_moderation_queue(actor UUID, after_escalated BOOLEAN, after_created_at TIMESTAMPTZ, after_case UUID)
RETURNS TABLE(case_id UUID,post_id UUID,comment_id UUID,reason TEXT,status TEXT,revision BIGINT,escalated BOOLEAN,created_at TIMESTAMPTZ)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT r.case_id,r.post_id,r.comment_id,r.reason,r.status,r.revision,r.escalated,r.created_at
    FROM public.content_reports r JOIN public.content_posts p ON p.id=r.post_id
    LEFT JOIN public.content_comments c ON c.id=r.comment_id
    WHERE (r.status='pending' OR (r.status='reviewing' AND (r.assigned_to=actor OR r.assigned_until<=statement_timestamp())))
        AND r.reporter_id IS DISTINCT FROM actor AND p.author_id<>actor AND (c.author_id IS NULL OR c.author_id<>actor)
        AND NOT EXISTS(SELECT 1 FROM public.content_author_purges q WHERE q.author_id IN (r.reporter_id,p.author_id,c.author_id,actor))
        AND (after_case IS NULL OR
            (NOT r.escalated,r.created_at,r.case_id) > (NOT after_escalated,after_created_at,after_case))
    ORDER BY NOT r.escalated,r.created_at,r.case_id LIMIT 51
$$;

REVOKE ALL ON FUNCTION content_moderation_queue(UUID,BOOLEAN,TIMESTAMPTZ,UUID) FROM PUBLIC;
