-- Keep a case identity independent from the account that submitted it.
ALTER TABLE content_reports DROP CONSTRAINT content_reports_pkey;
ALTER TABLE content_reports
    ALTER COLUMN reporter_id DROP NOT NULL,
    ALTER COLUMN id DROP NOT NULL,
    ADD CONSTRAINT content_report_request_pair CHECK ((reporter_id IS NULL) = (id IS NULL)),
    ADD CONSTRAINT content_report_request_unique UNIQUE(reporter_id,id);

DROP TRIGGER content_report_delete_releases_provisional_hide ON content_reports;
DROP FUNCTION content_release_provisional_report_hide();

CREATE FUNCTION content_erase_reporter(viewer UUID) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    batch UUID[];
BEGIN
    SELECT ARRAY(
        SELECT case_id FROM public.content_reports
        WHERE reporter_id=viewer ORDER BY id LIMIT 500 FOR UPDATE
    ) INTO batch;
    IF cardinality(batch)=0 THEN RETURN FALSE; END IF;

    -- Preserve safety cases and the evidence of any action already taken.
    UPDATE public.content_reports r SET reporter_id=NULL,id=NULL
    WHERE r.case_id=ANY(batch) AND (
        r.reason IN ('consent','age_safety')
        OR EXISTS (SELECT 1 FROM public.content_moderation_events e WHERE e.case_id=r.case_id)
    );

    DELETE FROM public.content_reports
    WHERE case_id=ANY(batch) AND reporter_id=viewer;
    RETURN TRUE;
END;
$$;
REVOKE ALL ON FUNCTION content_erase_reporter(UUID) FROM PUBLIC;

CREATE OR REPLACE FUNCTION content_purge_reporter(viewer UUID) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
    IF NOT EXISTS(SELECT 1 FROM public.content_author_purges WHERE author_id=viewer) THEN
        RAISE EXCEPTION 'missing reporter purge marker';
    END IF;
    RETURN public.content_erase_reporter(viewer);
END;
$$;

CREATE OR REPLACE FUNCTION content_moderation_queue(actor UUID)
RETURNS TABLE(case_id UUID,post_id UUID,comment_id UUID,reason TEXT,status TEXT,revision BIGINT,escalated BOOLEAN,created_at TIMESTAMPTZ)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT r.case_id,r.post_id,r.comment_id,r.reason,r.status,r.revision,r.escalated,r.created_at
    FROM public.content_reports r JOIN public.content_posts p ON p.id=r.post_id
    LEFT JOIN public.content_comments c ON c.id=r.comment_id
    WHERE (r.status='pending' OR (r.status='reviewing' AND (r.assigned_to=actor OR r.assigned_until<=statement_timestamp())))
        AND r.reporter_id IS DISTINCT FROM actor AND p.author_id<>actor AND (c.author_id IS NULL OR c.author_id<>actor)
        AND NOT EXISTS(SELECT 1 FROM public.content_author_purges q WHERE q.author_id IN (r.reporter_id,p.author_id,c.author_id,actor))
    ORDER BY r.escalated DESC,r.created_at,r.case_id LIMIT 50
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
            IF item.escalated THEN RETURN 0; END IF;
            UPDATE public.content_reports SET status='pending',assigned_to=NULL,assigned_until=NULL,escalated=TRUE,revision=revision+1 WHERE case_id=target;
        WHEN 'hide' THEN
            IF NOT public.content_set_moderation_hide(item,TRUE) THEN RETURN 0; END IF;
            UPDATE public.content_reports SET revision=revision+1 WHERE case_id=target;
        WHEN 'dismiss' THEN
            PERFORM public.content_set_moderation_hide(item,FALSE);
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
