ALTER TABLE content_purge_events
    ADD COLUMN media_finished BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN media_retry_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP;

CREATE INDEX content_purge_media_due_idx ON content_purge_events (media_retry_at, user_id)
    WHERE NOT media_finished;
