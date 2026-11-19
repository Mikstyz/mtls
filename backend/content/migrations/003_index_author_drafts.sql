CREATE INDEX content_posts_author_drafts_idx
    ON content_posts (author_id, created_at DESC, id DESC)
    WHERE status = 'draft' AND visibility = 'private';
