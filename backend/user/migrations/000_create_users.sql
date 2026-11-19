CREATE TABLE users (
    id UUID PRIMARY KEY,
    nickname TEXT NOT NULL CHECK (char_length(nickname) BETWEEN 1 AND 64),
    created_at TIMESTAMPTZ NOT NULL,
    last_online TIMESTAMPTZ
);
