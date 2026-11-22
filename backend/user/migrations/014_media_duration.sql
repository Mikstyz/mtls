ALTER TABLE media_permissions ADD COLUMN duration_ms BIGINT
    CHECK(duration_ms IS NULL OR (media_kind IS NOT DISTINCT FROM 'video' AND duration_ms BETWEEN 1 AND 86400000));
