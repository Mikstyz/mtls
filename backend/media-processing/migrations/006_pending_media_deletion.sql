ALTER TABLE media_assets ADD COLUMN files_removed_at TIMESTAMPTZ,
    ADD COLUMN delete_retry_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ADD CONSTRAINT media_removal_requires_deletion
        CHECK (files_removed_at IS NULL OR state = 'deleting');

CREATE INDEX media_pending_deletion_idx ON media_assets (delete_retry_at, id)
    WHERE state = 'deleting' AND files_removed_at IS NULL;
