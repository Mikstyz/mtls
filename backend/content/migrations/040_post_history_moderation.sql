LOCK TABLE content_posts IN SHARE ROW EXCLUSIVE MODE;

ALTER TABLE content_post_history
    ADD COLUMN event_id BIGINT GENERATED ALWAYS AS IDENTITY,
    DROP CONSTRAINT content_post_history_pkey,
    DROP CONSTRAINT content_post_history_operation_check,
    ADD PRIMARY KEY (post_id, revision, event_id),
    ADD CONSTRAINT content_post_history_operation_check CHECK (operation IN (
        'snapshot','created','published','removed','restored','moderation_changed',
        'moderation_hidden','moderation_unhidden'
    ));

CREATE OR REPLACE FUNCTION content_record_post_history() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    event TEXT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        event := 'created';
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
    AFTER INSERT OR UPDATE OF status, visibility, author_removed_at, hidden_by_case ON content_posts
    FOR EACH ROW EXECUTE FUNCTION content_record_post_history();
