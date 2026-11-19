CREATE INDEX sessions_revoked_at_idx ON sessions (revoked_at) WHERE revoked_at IS NOT NULL;

CREATE TABLE user_session_history (
    user_id UUID PRIMARY KEY REFERENCES credentials (user_id) ON DELETE CASCADE,
    last_seen_at TIMESTAMPTZ NOT NULL
);
