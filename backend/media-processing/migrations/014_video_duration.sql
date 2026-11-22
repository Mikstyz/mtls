ALTER TABLE media_assets ADD COLUMN duration_ms BIGINT
    CHECK(duration_ms IS NULL OR (kind='video' AND duration_ms BETWEEN 1 AND 86400000));
