CREATE TABLE content_scheduled_posts (
    post_id UUID PRIMARY KEY REFERENCES content_posts(id) ON DELETE CASCADE,
    schedule_id UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    revision BIGINT NOT NULL CHECK(revision>0),
    publish_at TIMESTAMPTZ NOT NULL,
    next_attempt_at TIMESTAMPTZ NOT NULL,
    visibility TEXT NOT NULL CHECK(visibility IN ('public','private'))
);
CREATE INDEX content_scheduled_due_idx ON content_scheduled_posts(next_attempt_at,publish_at,post_id);

CREATE FUNCTION content_schedule_post(author UUID,target UUID,edition BIGINT,due_at TIMESTAMPTZ,target_visibility TEXT)
RETURNS INTEGER LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    draft public.content_posts%ROWTYPE;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || author::text,0));
    SELECT * INTO draft FROM public.content_posts p WHERE p.id=target AND p.author_id=author
      AND NOT EXISTS(SELECT 1 FROM public.content_author_purges WHERE author_id=author) FOR UPDATE;
    IF NOT FOUND THEN RETURN 404; END IF;
    IF draft.revision<>edition OR draft.status<>'draft' OR draft.hidden_by_case IS NOT NULL THEN RETURN 409; END IF;

    IF due_at IS NULL THEN
        DELETE FROM public.content_scheduled_posts WHERE post_id=target;
        RETURN 204;
    END IF;
    IF EXISTS(SELECT 1 FROM public.content_scheduled_posts WHERE post_id=target AND revision=edition
        AND publish_at=due_at AND visibility=target_visibility) THEN RETURN 204; END IF;
    IF due_at<=clock_timestamp() OR due_at<>date_trunc('minute',due_at)
       OR target_visibility NOT IN ('public','private')
       OR btrim(draft.title)='' OR NOT EXISTS(SELECT 1 FROM public.content_post_media WHERE post_id=target)
    THEN RETURN 400; END IF;

    INSERT INTO public.content_scheduled_posts AS s(post_id,revision,publish_at,next_attempt_at,visibility)
    VALUES(target,edition,due_at,due_at,target_visibility)
    ON CONFLICT(post_id) DO UPDATE SET schedule_id=gen_random_uuid(),revision=EXCLUDED.revision,
        publish_at=EXCLUDED.publish_at,next_attempt_at=EXCLUDED.next_attempt_at,visibility=EXCLUDED.visibility;
    RETURN 204;
END;
$$;

CREATE FUNCTION content_claim_scheduled_post()
RETURNS TABLE(schedule_id UUID,post_id UUID,author_id UUID,media_kind TEXT,media_ids UUID[])
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    WITH due AS (
        SELECT s.post_id FROM public.content_scheduled_posts s
        WHERE s.publish_at<=clock_timestamp() AND s.next_attempt_at<=clock_timestamp()
        ORDER BY s.next_attempt_at,s.publish_at,s.post_id LIMIT 1 FOR UPDATE OF s SKIP LOCKED
    ), claimed AS (
        UPDATE public.content_scheduled_posts s SET next_attempt_at=clock_timestamp()+INTERVAL '30 seconds'
        FROM due WHERE s.post_id=due.post_id RETURNING s.schedule_id,s.post_id
    )
    SELECT s.schedule_id,s.post_id,p.author_id,p.media_kind,
        ARRAY(SELECT m.media_id FROM public.content_post_media m WHERE m.post_id=p.id ORDER BY m.position)
    FROM claimed s JOIN public.content_posts p ON p.id=s.post_id
$$;

CREATE FUNCTION content_publish_scheduled_post(target UUID,job UUID,owner UUID) RETURNS BOOLEAN
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
    IF NOT FOUND THEN RETURN FALSE; END IF;

    SELECT public.content_publish_post(owner,target,item.revision,item.visibility) INTO changed;
    RETURN changed>0;
END;
$$;

-- Edits or publication invalidate the scheduled edition in the same transaction.
CREATE FUNCTION content_clear_outdated_schedule() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
    DELETE FROM public.content_scheduled_posts WHERE post_id=NEW.id AND revision<>NEW.revision;
    RETURN NEW;
END;
$$;
CREATE TRIGGER content_schedule_revision_changed AFTER UPDATE OF revision ON content_posts
    FOR EACH ROW WHEN(OLD.revision IS DISTINCT FROM NEW.revision) EXECUTE FUNCTION content_clear_outdated_schedule();

REVOKE ALL ON FUNCTION content_schedule_post(UUID,UUID,BIGINT,TIMESTAMPTZ,TEXT),
    content_claim_scheduled_post(),content_publish_scheduled_post(UUID,UUID,UUID),
    content_clear_outdated_schedule() FROM PUBLIC;
