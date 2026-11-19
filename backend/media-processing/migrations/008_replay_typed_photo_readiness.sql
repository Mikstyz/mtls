INSERT INTO media_ready_events (asset_id)
SELECT id FROM media_assets WHERE state = 'processed' AND kind = 'photo'
ON CONFLICT (asset_id) DO NOTHING;
