CREATE TABLE media_ready_events (
    asset_id UUID PRIMARY KEY REFERENCES media_assets(id),
    available_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX media_ready_events_available_idx ON media_ready_events (available_at, asset_id);

INSERT INTO media_ready_events (asset_id)
SELECT id FROM media_assets WHERE state = 'processed' AND kind = 'photo';
