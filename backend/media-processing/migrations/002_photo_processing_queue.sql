CREATE INDEX media_assets_photo_queue_idx ON media_assets (created_at, id)
    WHERE kind = 'photo' AND state IN ('reserved', 'processing');
