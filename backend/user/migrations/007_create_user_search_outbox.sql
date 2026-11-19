LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE;

CREATE TABLE user_search_events (
    version BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL,
    nickname TEXT NOT NULL,
    deleted BOOLEAN NOT NULL,
    lease_token UUID,
    lease_until TIMESTAMPTZ,
    CHECK (NOT deleted OR nickname = '')
);

CREATE INDEX user_search_events_user_id_idx ON user_search_events (user_id);

CREATE FUNCTION record_user_search_event() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        DELETE FROM user_search_events WHERE user_id = OLD.id;
        INSERT INTO user_search_events (user_id, nickname, deleted) VALUES (OLD.id, '', TRUE);
        RETURN OLD;
    END IF;

    INSERT INTO user_search_events (user_id, nickname, deleted) VALUES (NEW.id, NEW.nickname, FALSE);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER user_search_insert_delete
    AFTER INSERT OR DELETE ON users FOR EACH ROW EXECUTE FUNCTION record_user_search_event();

CREATE TRIGGER user_search_nickname_update
    AFTER UPDATE OF nickname ON users FOR EACH ROW
    WHEN (OLD.nickname IS DISTINCT FROM NEW.nickname)
    EXECUTE FUNCTION record_user_search_event();

INSERT INTO user_search_events (user_id, nickname, deleted)
SELECT id, nickname, FALSE FROM users;
