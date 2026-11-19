ALTER TABLE content_posts ADD COLUMN revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0);

CREATE FUNCTION content_guard_draft_edit() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.status <> 'draft' OR OLD.visibility <> 'private'
        OR NEW.status <> OLD.status OR NEW.visibility <> OLD.visibility
        OR NEW.revision <> OLD.revision + 1 THEN
        RAISE EXCEPTION 'invalid draft edit';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER content_guard_draft_edit
    BEFORE UPDATE OF title, description, revision ON content_posts
    FOR EACH ROW EXECUTE FUNCTION content_guard_draft_edit();
