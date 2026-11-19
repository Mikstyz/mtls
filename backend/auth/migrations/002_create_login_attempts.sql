CREATE TABLE login_attempts (
    key_hash BYTEA PRIMARY KEY,
    window_started TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL CHECK (attempts > 0)
);

CREATE INDEX login_attempts_window_started_idx ON login_attempts (window_started);
