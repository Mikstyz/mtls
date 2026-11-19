CREATE TABLE registration_provisions (
    user_id UUID PRIMARY KEY,
    nickname TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
