ALTER TABLE media_variants
    DROP CONSTRAINT media_variants_format_and_size,
    ADD CONSTRAINT media_variants_format_and_size CHECK (
        byte_size > 0 AND (
            (name IN ('original.jpg', 'preview.jpg', 'original.png', 'preview.png') AND byte_size <= 33554432)
            OR (name IN ('poster.jpg', 'poster-25.jpg', 'poster-60.jpg') AND byte_size <= 1048576)
            OR (name IN ('original.mp4', '720p.mp4', '1080p.mp4', '1440p.mp4', '2160p.mp4')
                AND byte_size <= 1099511627776)
            OR (name IN ('adaptive.m3u8', '720p.m3u8', '1080p.m3u8', '1440p.m3u8', '2160p.m3u8')
                AND byte_size <= 2097152)
        )
    );
