ALTER TABLE content_moderation_events DROP CONSTRAINT content_moderation_events_action_check;
ALTER TABLE content_moderation_events ADD CONSTRAINT content_moderation_events_action_check
    CHECK(action IN ('claim','release','escalate','hide','dismiss','confirm','remove'));

DROP TRIGGER content_points_confirm ON content_moderation_events;
CREATE TRIGGER content_points_confirm
    AFTER INSERT ON content_moderation_events FOR EACH ROW WHEN (NEW.action IN ('confirm','remove'))
    EXECUTE FUNCTION content_apply_points_decision();

CREATE OR REPLACE FUNCTION content_moderate_report(actor UUID,target UUID,request UUID,expected BIGINT,decision TEXT,rule_code TEXT,level TEXT)
RETURNS BIGINT LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    item public.content_reports%ROWTYPE;
    prior public.content_moderation_events%ROWTYPE;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || actor::text,0));
    SELECT r.* INTO item FROM public.content_reports r JOIN public.content_posts p ON p.id=r.post_id
    LEFT JOIN public.content_comments c ON c.id=r.comment_id
    WHERE r.case_id=target AND r.reporter_id IS DISTINCT FROM actor AND p.author_id<>actor
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
        WHEN 'hide' THEN
            IF NOT public.content_set_moderation_hide(item,TRUE) THEN RETURN 0; END IF;
            UPDATE public.content_reports SET revision=revision+1 WHERE case_id=target;
        WHEN 'dismiss' THEN
            PERFORM public.content_set_moderation_hide(item,FALSE);
            UPDATE public.content_reports SET status='dismissed',revision=revision+1 WHERE case_id=target;
        WHEN 'confirm', 'remove' THEN
            IF rule_code IS NULL OR level IS NULL THEN RETURN 0; END IF;
            IF decision='remove' AND NOT public.content_set_moderation_hide(item,TRUE) THEN
                IF item.comment_id IS NULL THEN
                    PERFORM 1 FROM public.content_posts
                    WHERE id=item.post_id AND status='published' AND published_at<=item.created_at
                        AND hidden_by_case=item.case_id
                    FOR UPDATE;
                ELSE
                    PERFORM 1 FROM public.content_comments
                    WHERE id=item.comment_id AND post_id=item.post_id AND body IS NOT NULL
                        AND hidden_by_case=item.case_id
                    FOR UPDATE;
                END IF;

                IF NOT FOUND THEN RETURN 0; END IF;
            END IF;
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

CREATE OR REPLACE FUNCTION content_owner_moderation(owner UUID)
RETURNS TABLE(case_id UUID,post_id UUID,comment_id UUID,status TEXT,rule TEXT,severity TEXT,
    hidden BOOLEAN,appeal TEXT,decision_at TIMESTAMPTZ)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT c.case_id,c.post_id,c.comment_id,c.status,COALESCE(e.rule,c.reason),e.severity,
      COALESCE(c.hidden_by_case=c.case_id,FALSE),
      CASE WHEN a.case_id IS NOT NULL THEN COALESCE(a.outcome,'pending') END,e.occurred_at
    FROM public.content_case_owners c
    JOIN LATERAL (
      SELECT rule,severity,occurred_at FROM public.content_moderation_events e
      WHERE e.case_id=c.case_id AND e.action IN ('hide','dismiss','confirm','remove')
      ORDER BY revision DESC LIMIT 1
    ) e ON TRUE
    LEFT JOIN public.content_moderation_appeals a ON a.case_id=c.case_id
    WHERE c.owner_id=owner AND (c.status='resolved' OR a.case_id IS NOT NULL OR EXISTS(
        SELECT 1 FROM public.content_moderation_events h WHERE h.case_id=c.case_id AND h.action='hide'))
      AND NOT EXISTS(SELECT 1 FROM public.content_author_purges WHERE author_id=owner)
    ORDER BY e.occurred_at DESC,c.case_id
    LIMIT 50
$$;
