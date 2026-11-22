ALTER TABLE content_posts ADD COLUMN hidden_by_case UUID;
ALTER TABLE content_comments ADD COLUMN hidden_by_case UUID;
ALTER TABLE content_moderation_events DROP CONSTRAINT content_moderation_events_action_check;
ALTER TABLE content_moderation_events ADD CONSTRAINT content_moderation_events_action_check
    CHECK(action IN ('claim','release','escalate','hide','dismiss','confirm'));

-- A hide holds visibility independently of the publication revision. Dismissing
-- the case therefore restores existing access rights to the same edition.
CREATE FUNCTION content_set_moderation_hide(item public.content_reports, hidden BOOLEAN)
RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
    IF item.comment_id IS NULL THEN
        IF hidden THEN
            UPDATE public.content_posts SET hidden_by_case=item.case_id
            WHERE id=item.post_id AND status='published' AND hidden_by_case IS NULL;
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
REVOKE ALL ON FUNCTION content_set_moderation_hide(public.content_reports,BOOLEAN) FROM PUBLIC;

CREATE OR REPLACE FUNCTION content_moderate_report(actor UUID,target UUID,request UUID,expected BIGINT,decision TEXT,rule_code TEXT,level TEXT)
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

CREATE OR REPLACE FUNCTION content_set_reaction(
    reaction_post UUID, reaction_author UUID, reaction_viewer UUID, reaction_kind TEXT, enabled BOOLEAN, allow_test BOOLEAN
) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    IF reaction_kind IS NULL OR reaction_kind NOT IN ('like', 'favorite') OR enabled IS NULL
        OR reaction_post IS NULL OR reaction_author IS NULL OR reaction_viewer IS NULL
        OR '00000000-0000-0000-0000-000000000000'::UUID IN (reaction_post, reaction_author, reaction_viewer) THEN
        RAISE EXCEPTION 'invalid reaction' USING ERRCODE = '22023';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || reaction_viewer::text, 0));
    PERFORM 1 FROM public.content_posts AS p
    WHERE p.id = reaction_post AND p.author_id = reaction_author AND p.status = 'published' AND p.hidden_by_case IS NULL
        AND ((p.visibility = 'public' OR p.author_id = reaction_viewer OR (p.visibility='private' AND allow_test AND public.content_test_entitled(p.id,p.revision,reaction_viewer))))
        AND NOT EXISTS (
            SELECT 1 FROM public.content_author_purges a
            WHERE a.author_id IN (reaction_viewer, reaction_author)
        )
    FOR SHARE;

    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    IF reaction_kind = 'like' THEN
        IF enabled THEN
            INSERT INTO public.content_post_likes (post_id, viewer_id)
                VALUES (reaction_post, reaction_viewer) ON CONFLICT DO NOTHING;
            IF FOUND THEN
                INSERT INTO public.content_post_statistics (post_id, likes) VALUES (reaction_post, 1)
                ON CONFLICT (post_id) DO UPDATE SET likes = public.content_post_statistics.likes + 1;
            END IF;
        ELSE
            DELETE FROM public.content_post_likes WHERE post_id = reaction_post AND viewer_id = reaction_viewer;
            IF FOUND THEN
                UPDATE public.content_post_statistics SET likes = likes - 1 WHERE post_id = reaction_post;
                IF NOT FOUND THEN RAISE EXCEPTION 'missing post statistics'; END IF;
            END IF;
        END IF;
    ELSIF enabled THEN
        INSERT INTO public.content_post_favorites (post_id, viewer_id)
            VALUES (reaction_post, reaction_viewer) ON CONFLICT DO NOTHING;
    ELSE
        DELETE FROM public.content_post_favorites WHERE post_id = reaction_post AND viewer_id = reaction_viewer;
    END IF;

    RETURN TRUE;
END;
$$;

CREATE OR REPLACE FUNCTION content_write_comment(target UUID, actor UUID, comment_id UUID, message TEXT, allow_test BOOLEAN)
RETURNS INTEGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    previous public.content_comments%ROWTYPE;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || actor::text, 0));
    PERFORM 1 FROM public.content_posts p
    WHERE p.id=target AND p.status='published' AND p.hidden_by_case IS NULL AND ((p.visibility='public' OR p.author_id=actor OR (p.visibility='private' AND allow_test AND public.content_test_entitled(p.id,p.revision,actor))))
        AND NOT EXISTS (SELECT 1 FROM public.content_author_purges a WHERE a.author_id IN (actor,p.author_id))
    FOR SHARE;
    IF NOT FOUND THEN RETURN 404; END IF;

    SELECT * INTO previous FROM public.content_comments WHERE id=comment_id;
    IF FOUND THEN
        IF previous.author_id <> actor OR previous.post_id <> target THEN RETURN 404; END IF;
        IF message IS NULL THEN
            UPDATE public.content_comments SET body=NULL WHERE id=comment_id AND body IS NOT NULL;
            RETURN 204;
        END IF;
        IF previous.body IS DISTINCT FROM message THEN RETURN 409; END IF;
        RETURN 204;
    END IF;
    IF message IS NULL THEN RETURN 404; END IF;

    IF EXISTS (SELECT 1 FROM public.content_comments WHERE author_id=actor
        AND created_at > clock_timestamp() - INTERVAL '1 minute' OFFSET 4 LIMIT 1)
    THEN RETURN 429; END IF;

    INSERT INTO public.content_comments(id,post_id,author_id,body)
    VALUES(comment_id,target,actor,message) ON CONFLICT (id) DO NOTHING;
    IF NOT FOUND THEN RETURN 404; END IF;
    RETURN 201;
END;
$$;

CREATE OR REPLACE FUNCTION content_count_post_view(view_post UUID, view_media UUID, view_user UUID, observed_day INTEGER, allow_test BOOLEAN)
RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    today INTEGER := (clock_timestamp() AT TIME ZONE 'UTC')::DATE - DATE '1970-01-01';
BEGIN
    IF observed_day NOT BETWEEN today - 1 AND today THEN
        RETURN;
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || view_user::text, 0));
    PERFORM 1 FROM public.content_posts p
    JOIN public.content_post_media m ON m.post_id = p.id AND m.media_id = view_media
    WHERE p.id = view_post AND p.status = 'published' AND p.hidden_by_case IS NULL AND (p.visibility = 'public' OR (p.visibility='private' AND allow_test AND public.content_test_entitled(p.id,p.revision,view_user)))
        AND p.author_id <> view_user
        AND NOT EXISTS (
            SELECT 1 FROM public.content_author_purges a WHERE a.author_id IN (p.author_id, view_user)
        )
    FOR SHARE OF p;

    IF NOT FOUND THEN RETURN; END IF;

    INSERT INTO public.content_post_view_receipts (post_id, viewer_id, view_day)
        VALUES (view_post, view_user, observed_day)
    ON CONFLICT (post_id, viewer_id) DO UPDATE SET view_day = EXCLUDED.view_day
        WHERE public.content_post_view_receipts.view_day < EXCLUDED.view_day;

    IF FOUND THEN
        INSERT INTO public.content_post_statistics (post_id, views) VALUES (view_post, 1)
        ON CONFLICT (post_id) DO UPDATE SET views = public.content_post_statistics.views + 1;
    END IF;
END;
$$;

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

    INSERT INTO public.content_reports(reporter_id,id,post_id,comment_id,reason)
        VALUES(viewer,request,target,comment,category);
    RETURN 'created';
END;
$$;

CREATE OR REPLACE FUNCTION content_test_offer(target UUID, seller UUID, edition BIGINT, price BIGINT, unit TEXT)
RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || seller::text,0));
    PERFORM 1 FROM public.content_posts p WHERE p.id=target AND p.author_id=seller
        AND p.status='published' AND p.hidden_by_case IS NULL AND p.visibility='private' AND p.revision=edition
        AND NOT EXISTS(SELECT 1 FROM public.content_author_purges WHERE author_id=seller)
        FOR SHARE;
    IF NOT FOUND THEN RETURN FALSE; END IF;

    INSERT INTO public.content_test_offers(post_id,revision,amount_minor,currency)
        VALUES(target,edition,price,unit) ON CONFLICT DO NOTHING;
    RETURN EXISTS(SELECT 1 FROM public.content_test_offers WHERE post_id=target AND revision=edition
        AND amount_minor=price AND currency=unit);
END;
$$;

CREATE OR REPLACE FUNCTION content_test_purchase(target UUID, buyer UUID, operation UUID, edition BIGINT)
RETURNS INTEGER LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    previous public.content_test_orders%ROWTYPE;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || buyer::text,0));
    PERFORM 1 FROM public.content_posts p JOIN public.content_test_offers o
        ON o.post_id=p.id AND o.revision=p.revision
        WHERE p.id=target AND p.revision=edition AND p.visibility='private' AND p.status='published' AND p.hidden_by_case IS NULL
        AND p.author_id<>buyer AND NOT EXISTS(
            SELECT 1 FROM public.content_author_purges WHERE author_id IN (buyer,p.author_id))
        FOR SHARE OF p;
    IF NOT FOUND THEN RETURN 404; END IF;

    SELECT * INTO previous FROM public.content_test_orders WHERE buyer_id=buyer AND request_id=operation;
    IF FOUND THEN
        IF previous.revoked_at IS NULL AND previous.post_id=target AND previous.revision=edition THEN RETURN 200; END IF;
        RETURN 409;
    END IF;

    INSERT INTO public.content_test_orders(buyer_id,request_id,post_id,revision)
        VALUES(buyer,operation,target,edition) ON CONFLICT DO NOTHING;
    IF NOT FOUND THEN RETURN 409; END IF;
    RETURN 201;
END;
$$;

CREATE OR REPLACE FUNCTION content_record_search_event() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    was_public BOOLEAN := FALSE;
    is_public BOOLEAN := FALSE;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        was_public := OLD.status = 'published' AND OLD.visibility = 'public' AND OLD.hidden_by_case IS NULL;
    END IF;

    IF TG_OP <> 'DELETE' THEN
        is_public := NEW.status = 'published' AND NEW.visibility = 'public' AND NEW.hidden_by_case IS NULL;
    END IF;

    IF TG_OP = 'DELETE' THEN
        DELETE FROM public.content_search_events WHERE post_id = OLD.id;
        INSERT INTO public.content_search_events (post_id, title, deleted) VALUES (OLD.id, '', TRUE);
        RETURN OLD;
    END IF;

    IF is_public AND (NOT was_public OR TG_OP = 'INSERT' OR OLD.title IS DISTINCT FROM NEW.title) THEN
        INSERT INTO public.content_search_events (post_id, title, deleted) VALUES (NEW.id, NEW.title, FALSE);
    ELSIF was_public AND NOT is_public THEN
        DELETE FROM public.content_search_events WHERE post_id = NEW.id;
        INSERT INTO public.content_search_events (post_id, title, deleted) VALUES (NEW.id, '', TRUE);
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER content_search_visibility
    AFTER UPDATE OF hidden_by_case ON content_posts
    FOR EACH ROW EXECUTE FUNCTION content_record_search_event();

-- Reporter erasure releases provisional holds. A confirmed decision survives
-- independently of the reporter, so deletion cannot make the material visible.
CREATE FUNCTION content_release_provisional_report_hide() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
    IF OLD.status IN ('pending','reviewing') THEN
        PERFORM public.content_set_moderation_hide(OLD,FALSE);
    END IF;
    RETURN OLD;
END;
$$;
REVOKE ALL ON FUNCTION content_release_provisional_report_hide() FROM PUBLIC;
CREATE TRIGGER content_report_delete_releases_provisional_hide
    BEFORE DELETE ON content_reports
    FOR EACH ROW EXECUTE FUNCTION content_release_provisional_report_hide();
