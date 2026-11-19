CREATE TABLE registrations (
    user_id UUID PRIMARY KEY REFERENCES credentials (user_id) ON DELETE CASCADE,
    nickname TEXT NOT NULL CHECK (char_length(nickname) BETWEEN 1 AND 64),
    token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    expires_at TIMESTAMPTZ NOT NULL,
    confirmed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX registrations_expires_at_idx ON registrations (expires_at);
