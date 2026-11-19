CREATE TABLE account_deletions (
    user_id UUID PRIMARY KEY REFERENCES credentials (user_id) ON DELETE CASCADE,
    deleted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    state TEXT NOT NULL CHECK (state IN ('deleting', 'deleted', 'restoring_owner', 'restoring_moderator', 'purging')),
    operation_id UUID NOT NULL,
    lease_id UUID,
    lease_until TIMESTAMPTZ,
    available_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    CHECK ((lease_id IS NULL) = (lease_until IS NULL))
);

CREATE INDEX account_deletions_state_available_idx ON account_deletions (state, available_at);

CREATE TABLE account_roles (
    user_id UUID NOT NULL REFERENCES credentials (user_id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('moderator')),
    PRIMARY KEY (user_id, role)
);
