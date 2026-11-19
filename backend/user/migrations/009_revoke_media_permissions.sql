ALTER TABLE media_permissions
    ADD COLUMN revoked_at TIMESTAMPTZ,
    ADD CONSTRAINT media_revocation_closes_access
        CHECK (revoked_at IS NULL OR (NOT ready AND visibility = 'private'));
