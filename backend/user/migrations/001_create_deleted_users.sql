CREATE TABLE deleted_users (
    id UUID PRIMARY KEY,
    nickname TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    last_online TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX deleted_users_deleted_at_idx ON deleted_users (deleted_at);
