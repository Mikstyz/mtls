CREATE TABLE user_presence (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id UUID NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (user_id, session_id)
);

CREATE INDEX user_presence_last_seen_idx ON user_presence (last_seen);
