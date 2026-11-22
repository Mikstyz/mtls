UPDATE content_reports SET escalated=TRUE
WHERE status IN ('pending','reviewing') AND reason IN ('consent','age_safety') AND NOT escalated;

CREATE OR REPLACE FUNCTION content_submit_report(viewer UUID, request UUID, target UUID, comment UUID, category TEXT,
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

    PERFORM 1 FROM public.content_posts p WHERE p.id=target AND p.status='published' AND p.hidden_by_case IS NULL
        AND (p.visibility='public' OR p.author_id=viewer
            OR (p.visibility='private' AND allow_test
                AND has_function_privilege(session_user,'public.content_test_purchase(uuid,uuid,uuid,bigint)','EXECUTE')
                AND public.content_test_entitled(p.id,p.revision,viewer)))
        AND NOT EXISTS (SELECT 1 FROM public.content_author_purges WHERE author_id=p.author_id)
        FOR SHARE;
    IF NOT FOUND THEN RETURN 'missing'; END IF;

    IF comment IS NOT NULL THEN
        PERFORM 1 FROM public.content_comments c
        WHERE c.id=comment AND c.post_id=target AND c.body IS NOT NULL AND c.hidden_by_case IS NULL
            AND NOT EXISTS (SELECT 1 FROM public.content_author_purges WHERE author_id=c.author_id)
            FOR SHARE;
        IF NOT FOUND THEN RETURN 'missing'; END IF;
    END IF;

    IF EXISTS (SELECT 1 FROM public.content_reports WHERE reporter_id=viewer
        AND post_id=target AND comment_id IS NOT DISTINCT FROM comment) THEN RETURN 'conflict'; END IF;
    IF EXISTS (SELECT 1 FROM public.content_reports WHERE reporter_id=viewer
        AND created_at>clock_timestamp()-INTERVAL '1 hour' LIMIT 1 OFFSET 4) THEN RETURN 'limited'; END IF;

    INSERT INTO public.content_reports(reporter_id,id,post_id,comment_id,reason,escalated)
        VALUES(viewer,request,target,comment,category,category IN ('consent','age_safety'));
    RETURN 'created';
END;
$$;

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
            IF EXISTS (
                SELECT 1 FROM public.content_moderation_events
                WHERE case_id=target AND action='escalate'
            ) THEN RETURN 0; END IF;
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
