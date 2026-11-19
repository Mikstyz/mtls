LOCK TABLE content_posts IN SHARE ROW EXCLUSIVE MODE;

CREATE TABLE content_search_events (
    version BIGSERIAL PRIMARY KEY,
    post_id UUID NOT NULL,
    title TEXT NOT NULL CHECK (octet_length(title) <= 4096),
    deleted BOOLEAN NOT NULL,
    lease_token UUID,
    lease_until TIMESTAMPTZ,
    CHECK (NOT deleted OR title = ''),
    CHECK ((lease_token IS NULL) = (lease_until IS NULL))
);

CREATE INDEX content_search_events_post_id_idx ON content_search_events (post_id);

CREATE FUNCTION content_record_search_event() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    was_public BOOLEAN := FALSE;
    is_public BOOLEAN := FALSE;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        was_public := OLD.status = 'published' AND OLD.visibility = 'public';
    END IF;

    IF TG_OP <> 'DELETE' THEN
        is_public := NEW.status = 'published' AND NEW.visibility = 'public';
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

REVOKE ALL ON FUNCTION content_record_search_event() FROM PUBLIC;

CREATE TRIGGER content_search_insert_delete
    AFTER INSERT OR DELETE ON content_posts FOR EACH ROW EXECUTE FUNCTION content_record_search_event();

CREATE TRIGGER content_search_update
    AFTER UPDATE OF title, status, visibility ON content_posts
    FOR EACH ROW EXECUTE FUNCTION content_record_search_event();

INSERT INTO content_search_events (post_id, title, deleted)
SELECT id, title, FALSE FROM content_posts WHERE status = 'published' AND visibility = 'public';
