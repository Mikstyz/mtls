CREATE INDEX media_upload_history_owner_idx ON media_assets (owner_id, created_at DESC, id DESC);
