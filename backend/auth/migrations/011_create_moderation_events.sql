CREATE TABLE account_moderation_events (
    operation_id UUID PRIMARY KEY,
    actor_id UUID REFERENCES credentials (user_id) ON DELETE SET NULL,
    target_id UUID NOT NULL REFERENCES credentials (user_id) ON DELETE CASCADE,
    action TEXT NOT NULL CHECK (action = 'restore'),
    outcome TEXT NOT NULL CHECK (outcome IN ('requested', 'completed', 'rejected')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX account_moderation_events_target_idx ON account_moderation_events (target_id, created_at);
