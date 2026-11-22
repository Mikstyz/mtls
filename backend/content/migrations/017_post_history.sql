LOCK TABLE content_posts IN SHARE ROW EXCLUSIVE MODE;

CREATE TABLE content_post_history (
    post_id UUID NOT NULL REFERENCES content_posts(id) ON DELETE CASCADE,
    revision BIGINT NOT NULL CHECK (revision > 0),
    state TEXT NOT NULL CHECK (state IN ('draft','published','removed')),
    visibility TEXT NOT NULL CHECK (visibility IN ('private','public','paid')),
    operation TEXT NOT NULL CHECK (operation IN (
        'snapshot','created','published','removed','restored','moderation_changed'
    )),
    changed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (post_id, revision)
);

-- Existing rows provide a baseline. Their earlier transitions cannot be inferred.
INSERT INTO content_post_history(post_id,revision,state,visibility,operation)
SELECT id,revision,status,visibility,'snapshot' FROM content_posts;

CREATE FUNCTION content_record_post_history() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    event TEXT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        event := 'created';
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

REVOKE ALL ON FUNCTION content_record_post_history() FROM PUBLIC;

CREATE TRIGGER content_record_post_history
    AFTER INSERT OR UPDATE OF status, visibility, author_removed_at ON content_posts
    FOR EACH ROW EXECUTE FUNCTION content_record_post_history();
