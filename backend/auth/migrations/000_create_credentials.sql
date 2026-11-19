CREATE TABLE credentials (
    user_id UUID PRIMARY KEY,
    login TEXT NOT NULL UNIQUE CHECK (login = lower(login)),
    email TEXT NOT NULL UNIQUE CHECK (email = lower(email)),
    password_version SMALLINT NOT NULL DEFAULT 1,
    password_salt BYTEA NOT NULL CHECK (octet_length(password_salt) = 16),
    password_hash BYTEA NOT NULL CHECK (octet_length(password_hash) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
