CREATE TABLE content_revoked_media (
    media_id UUID PRIMARY KEY,
    owner_id UUID NOT NULL
);
CREATE INDEX content_revoked_media_owner_idx ON content_revoked_media(owner_id);
CREATE INDEX content_post_media_asset_idx ON content_post_media(media_id,post_id);
CREATE INDEX content_video_covers_asset_idx ON content_video_covers(media_id,post_id);

ALTER TABLE content_posts ADD COLUMN last_media_revoked_at TIMESTAMPTZ;

ALTER TABLE content_post_history DROP CONSTRAINT content_post_history_operation_check;
ALTER TABLE content_post_history ADD CONSTRAINT content_post_history_operation_check CHECK (operation IN (
    'snapshot','created','published','removed','restored','moderation_changed',
    'moderation_hidden','moderation_unhidden','media_revoked'
));

CREATE OR REPLACE FUNCTION content_record_post_history() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    event TEXT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        event := 'created';
    ELSIF NEW.last_media_revoked_at IS DISTINCT FROM OLD.last_media_revoked_at THEN
        event := 'media_revoked';
    ELSIF NEW.hidden_by_case IS DISTINCT FROM OLD.hidden_by_case THEN
        IF NEW.hidden_by_case IS NULL THEN
            event := 'moderation_unhidden';
        ELSE
            event := 'moderation_hidden';
        END IF;
    ELSIF (NEW.status,NEW.visibility,NEW.author_removed_at)
        IS NOT DISTINCT FROM (OLD.status,OLD.visibility,OLD.author_removed_at) THEN
        RETURN NEW;
    ELSIF NEW.status = 'published' THEN
        event := 'published';
    ELSIF NEW.status = 'removed' AND NEW.author_removed_at IS NOT NULL THEN
        event := 'removed';
    ELSIF NEW.status = 'draft' AND OLD.author_removed_at IS NOT NULL THEN
        event := 'restored';
    ELSE
        event := 'moderation_changed';
    END IF;

    INSERT INTO public.content_post_history(post_id,revision,state,visibility,operation)
        VALUES(NEW.id,NEW.revision,NEW.status,NEW.visibility,event);
    RETURN NEW;
END;
$$;

DROP TRIGGER content_record_post_history ON content_posts;
CREATE TRIGGER content_record_post_history
    AFTER INSERT OR UPDATE OF status, visibility, author_removed_at, hidden_by_case, last_media_revoked_at ON content_posts
    FOR EACH ROW EXECUTE FUNCTION content_record_post_history();

CREATE OR REPLACE FUNCTION content_set_draft_media(
    draft_author UUID, draft_id UUID, expected_revision BIGINT, attachments UUID[]
) RETURNS BIGINT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    active_revision BIGINT;
    current_attachments UUID[];
BEGIN
    IF attachments IS NULL OR cardinality(attachments) > 16
        OR EXISTS (SELECT 1 FROM unnest(attachments) AS item(id)
            GROUP BY id HAVING id IS NULL OR id = '00000000-0000-0000-0000-000000000000' OR count(*) > 1)
        OR expected_revision IS NULL OR expected_revision < 1 THEN
        RAISE EXCEPTION 'invalid draft attachments' USING ERRCODE = '22023';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || draft_author::text, 0));

    SELECT revision INTO active_revision FROM public.content_posts
    WHERE id = draft_id AND author_id = draft_author AND status = 'draft' AND visibility = 'private'
        AND NOT EXISTS (SELECT 1 FROM public.content_author_purges WHERE author_id = draft_author)
    FOR UPDATE;
    IF NOT FOUND THEN RETURN -1; END IF;

    SELECT COALESCE(array_agg(media_id ORDER BY position), ARRAY[]::UUID[])
    INTO current_attachments FROM public.content_post_media WHERE post_id = draft_id;

    IF current_attachments = attachments AND active_revision IN (expected_revision, expected_revision + 1::numeric) THEN
        RETURN active_revision;
    END IF;

    IF active_revision <> expected_revision OR EXISTS (
        SELECT 1 FROM public.content_revoked_media WHERE owner_id=draft_author AND media_id=ANY(attachments)
    ) THEN RETURN 0; END IF;

    DELETE FROM public.content_post_media WHERE post_id = draft_id;
    INSERT INTO public.content_post_media (post_id, media_id, position)
        SELECT draft_id, item.id, (item.position - 1)::INTEGER
        FROM unnest(attachments) WITH ORDINALITY AS item(id, position);

    UPDATE public.content_posts SET revision = revision + 1 WHERE id = draft_id
        RETURNING revision INTO active_revision;
    RETURN active_revision;
END;
$$;

CREATE OR REPLACE FUNCTION content_set_video_cover(owner UUID,target UUID,expected BIGINT,photo UUID, frame TEXT)
RETURNS BIGINT LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    current_revision BIGINT;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || owner::text,0));
    SELECT revision INTO current_revision FROM public.content_posts
    WHERE id=target AND author_id=owner AND media_kind='video' AND status IN ('draft','published')
        AND NOT EXISTS(SELECT 1 FROM public.content_author_purges WHERE author_id=owner)
    FOR UPDATE;
    IF NOT FOUND THEN RETURN -1; END IF;
    IF current_revision<>expected OR EXISTS (
        SELECT 1 FROM public.content_revoked_media WHERE owner_id=owner AND media_id=photo
    ) THEN RETURN 0; END IF;

    IF frame IS NOT NULL AND (
        frame NOT IN ('poster-25.jpg','poster-60.jpg') OR photo IS NULL OR photo IS DISTINCT FROM
            (SELECT media_id FROM public.content_post_media WHERE post_id=target ORDER BY position LIMIT 1)
    ) THEN RETURN 0; END IF;

    IF photo IS NULL THEN
        DELETE FROM public.content_video_covers WHERE post_id=target;
    ELSE
        INSERT INTO public.content_video_covers(post_id,media_id,frame_name) VALUES(target,photo,frame)
        ON CONFLICT(post_id) DO UPDATE SET media_id=EXCLUDED.media_id,frame_name=EXCLUDED.frame_name;
    END IF;
    RETURN current_revision;
END;
$$;

CREATE FUNCTION content_revoke_media_attachment(owner UUID, media UUID) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    recorded_owner UUID;
BEGIN
    IF owner IS NULL OR media IS NULL THEN RETURN FALSE; END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || owner::text,0));
    IF EXISTS (SELECT 1 FROM public.content_author_purges WHERE author_id=owner) THEN RETURN TRUE; END IF;

    INSERT INTO public.content_revoked_media(media_id,owner_id) VALUES(media,owner)
    ON CONFLICT (media_id) DO NOTHING;
    IF NOT FOUND THEN
        SELECT owner_id INTO STRICT recorded_owner FROM public.content_revoked_media WHERE media_id=media;
        RETURN recorded_owner=owner;
    END IF;

    DELETE FROM public.content_video_covers c USING public.content_posts p
    WHERE c.post_id=p.id AND c.media_id=media AND p.author_id=owner;

    WITH removed AS (
        DELETE FROM public.content_post_media m USING public.content_posts p
        WHERE m.post_id=p.id AND m.media_id=media AND p.author_id=owner
        RETURNING m.post_id
    )
    UPDATE public.content_posts p SET
        status=CASE WHEN p.status='published' THEN 'removed' ELSE p.status END,
        author_removed_at=CASE WHEN p.status='published' THEN clock_timestamp() ELSE p.author_removed_at END,
        last_media_revoked_at=clock_timestamp(),
        revision=p.revision+1
    FROM removed WHERE p.id=removed.post_id AND p.status IN ('draft','published');

    RETURN TRUE;
END;
$$;

CREATE FUNCTION content_purge_revoked_media() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
    DELETE FROM public.content_revoked_media WHERE owner_id=NEW.author_id;
    RETURN NEW;
END;
$$;

CREATE TRIGGER content_purge_revoked_media AFTER INSERT ON content_author_purges
    FOR EACH ROW EXECUTE FUNCTION content_purge_revoked_media();

REVOKE ALL ON FUNCTION content_revoke_media_attachment(UUID,UUID),content_purge_revoked_media() FROM PUBLIC;
