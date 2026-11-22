CREATE OR REPLACE FUNCTION content_claim_scheduled_post()
RETURNS TABLE(schedule_id UUID,post_id UUID,author_id UUID,media_kind TEXT,media_ids UUID[])
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    WITH due AS (
        SELECT s.post_id FROM public.content_scheduled_posts s
        WHERE s.publish_at<=clock_timestamp() AND s.next_attempt_at<=clock_timestamp()
        ORDER BY s.next_attempt_at,s.publish_at,s.post_id LIMIT 1 FOR UPDATE OF s SKIP LOCKED
    ), claimed AS (
        UPDATE public.content_scheduled_posts s
        SET schedule_id=gen_random_uuid(),next_attempt_at=clock_timestamp()+INTERVAL '30 seconds'
        FROM due WHERE s.post_id=due.post_id RETURNING s.schedule_id,s.post_id
    )
    SELECT s.schedule_id,s.post_id,p.author_id,p.media_kind,
        ARRAY(SELECT m.media_id FROM public.content_post_media m WHERE m.post_id=p.id ORDER BY m.position)
    FROM claimed s JOIN public.content_posts p ON p.id=s.post_id
$$;

CREATE OR REPLACE FUNCTION content_publish_scheduled_post(target UUID,job UUID,owner UUID,duration BIGINT) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    item public.content_scheduled_posts%ROWTYPE;
    changed BIGINT;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || owner::text,0));
    PERFORM 1 FROM public.content_posts WHERE id=target AND author_id=owner
        AND status='draft' AND hidden_by_case IS NULL FOR UPDATE;
    IF NOT FOUND THEN RETURN FALSE; END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('content-points:' || owner::text,0));
    IF EXISTS(SELECT 1 FROM public.content_active_points_ban(owner)) THEN RETURN FALSE; END IF;
    SELECT * INTO item FROM public.content_scheduled_posts
        WHERE schedule_id=job AND post_id=target AND publish_at<=clock_timestamp() FOR UPDATE;
    IF NOT FOUND OR item.next_attempt_at<=clock_timestamp() THEN RETURN FALSE; END IF;

    SELECT public.content_publish_post_duration(owner,target,item.revision,item.visibility,duration) INTO changed;
    RETURN changed>0;
END;
$$;
