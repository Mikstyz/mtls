ALTER TABLE content_reports
    ADD COLUMN case_id UUID NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    ADD COLUMN assigned_to UUID,
    ADD COLUMN assigned_until TIMESTAMPTZ,
    ADD COLUMN revision BIGINT NOT NULL DEFAULT 1 CHECK(revision>0),
    ADD COLUMN escalated BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX content_report_assigned_idx ON content_reports(assigned_to,created_at,case_id)
    WHERE status='reviewing';

CREATE TABLE content_moderation_events (
    case_id UUID NOT NULL REFERENCES content_reports(case_id) ON DELETE CASCADE,
    revision BIGINT NOT NULL,
    request_id UUID NOT NULL,
    actor_id UUID NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('claim','release','escalate','dismiss','confirm')),
    rule TEXT,
    severity TEXT CHECK(severity IN ('low','medium','high','critical')),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(case_id,revision),
    UNIQUE(case_id,request_id)
);

CREATE FUNCTION content_moderation_queue(actor UUID)
RETURNS TABLE(case_id UUID,post_id UUID,comment_id UUID,reason TEXT,status TEXT,revision BIGINT,escalated BOOLEAN,created_at TIMESTAMPTZ)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT r.case_id,r.post_id,r.comment_id,r.reason,r.status,r.revision,r.escalated,r.created_at
    FROM public.content_reports r JOIN public.content_posts p ON p.id=r.post_id
    LEFT JOIN public.content_comments c ON c.id=r.comment_id
    WHERE (r.status='pending' OR (r.status='reviewing' AND (r.assigned_to=actor OR r.assigned_until<=statement_timestamp())))
        AND r.reporter_id<>actor AND p.author_id<>actor AND (c.author_id IS NULL OR c.author_id<>actor)
        AND NOT EXISTS(SELECT 1 FROM public.content_author_purges q WHERE q.author_id IN (r.reporter_id,p.author_id,c.author_id,actor))
    ORDER BY r.escalated DESC,r.created_at,r.case_id LIMIT 50
$$;

CREATE FUNCTION content_moderate_report(actor UUID,target UUID,request UUID,expected BIGINT,decision TEXT,rule_code TEXT,level TEXT)
RETURNS BIGINT LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    item public.content_reports%ROWTYPE;
    prior public.content_moderation_events%ROWTYPE;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || actor::text,0));
    SELECT r.* INTO item FROM public.content_reports r JOIN public.content_posts p ON p.id=r.post_id
    LEFT JOIN public.content_comments c ON c.id=r.comment_id
    WHERE r.case_id=target AND r.reporter_id<>actor AND p.author_id<>actor
        AND (c.author_id IS NULL OR c.author_id<>actor)
        AND NOT EXISTS(SELECT 1 FROM public.content_author_purges q WHERE q.author_id IN (r.reporter_id,p.author_id,c.author_id,actor))
    FOR UPDATE OF r;
    IF NOT FOUND THEN RETURN -1; END IF;

    SELECT * INTO prior FROM public.content_moderation_events WHERE case_id=target AND request_id=request;
    IF FOUND THEN
        IF prior.actor_id=actor AND prior.revision=expected+1 AND prior.action=decision
            AND prior.rule IS NOT DISTINCT FROM rule_code AND prior.severity IS NOT DISTINCT FROM level
        THEN RETURN prior.revision; END IF;
        RETURN 0;
    END IF;

    IF item.revision<>expected THEN RETURN 0; END IF;
    IF decision='claim' AND (item.status='pending' OR
        (item.status='reviewing' AND item.assigned_until<=clock_timestamp())) THEN
        UPDATE public.content_reports SET status='reviewing',assigned_to=actor,assigned_until=clock_timestamp()+INTERVAL '24 hours',revision=revision+1 WHERE case_id=target;
    ELSIF item.status='reviewing' AND item.assigned_to=actor AND item.assigned_until>clock_timestamp() THEN
        CASE decision
        WHEN 'release' THEN
            UPDATE public.content_reports SET status='pending',assigned_to=NULL,assigned_until=NULL,revision=revision+1 WHERE case_id=target;
        WHEN 'escalate' THEN
            IF item.escalated THEN RETURN 0; END IF;
            UPDATE public.content_reports SET status='pending',assigned_to=NULL,assigned_until=NULL,escalated=TRUE,revision=revision+1 WHERE case_id=target;
        WHEN 'dismiss' THEN
            UPDATE public.content_reports SET status='dismissed',revision=revision+1 WHERE case_id=target;
        WHEN 'confirm' THEN
            IF rule_code IS NULL OR level IS NULL THEN RETURN 0; END IF;
            UPDATE public.content_reports SET status='resolved',revision=revision+1 WHERE case_id=target;
        ELSE RETURN 0;
        END CASE;
    ELSE RETURN 0;
    END IF;

    INSERT INTO public.content_moderation_events(case_id,revision,request_id,actor_id,action,rule,severity)
        VALUES(target,expected+1,request,actor,decision,rule_code,level);
    RETURN expected+1;
END;
$$;
REVOKE ALL ON FUNCTION content_moderation_queue(UUID),
    content_moderate_report(UUID,UUID,UUID,BIGINT,TEXT,TEXT,TEXT) FROM PUBLIC;
