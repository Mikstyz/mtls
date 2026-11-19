CREATE TABLE account_lifecycle_operations (
    operation_id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('deleting', 'restoring_owner', 'restoring_moderator', 'purging')),
    deleted_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX account_lifecycle_operations_user_id_idx ON account_lifecycle_operations (user_id);
