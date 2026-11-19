ALTER TABLE media_permissions ADD COLUMN media_kind TEXT CHECK (media_kind IN ('photo', 'video'));
