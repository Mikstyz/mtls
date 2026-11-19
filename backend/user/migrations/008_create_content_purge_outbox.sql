CREATE TABLE content_purge_events (
    user_id UUID PRIMARY KEY,
    lease_token UUID,
    lease_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
