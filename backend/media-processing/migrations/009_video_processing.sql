ALTER TABLE media_assets RENAME COLUMN photo_attempts TO processing_attempts;
ALTER TABLE media_assets RENAME COLUMN photo_retry_at TO processing_retry_at;

CREATE INDEX media_assets_video_queue_idx ON media_assets (created_at, id)
    WHERE kind = 'video' AND state IN ('reserved', 'processing');

ALTER TABLE media_variants
    DROP CONSTRAINT media_variants_name_check,
    DROP CONSTRAINT media_variants_byte_size_check,
    ADD CONSTRAINT media_variants_format_and_size CHECK (
        byte_size > 0 AND (
            (name IN ('original.jpg', 'preview.jpg', 'original.png', 'preview.png') AND byte_size <= 33554432)
            OR (name IN ('original.mp4', '720p.mp4', '1080p.mp4', '1440p.mp4', '2160p.mp4')
                AND byte_size <= 1099511627776)
        )
    );
