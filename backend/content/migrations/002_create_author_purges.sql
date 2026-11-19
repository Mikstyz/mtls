ALTER TABLE content_posts ADD CONSTRAINT content_posts_author_id_id_unique UNIQUE (author_id, id);

ALTER TABLE content_draft_requests ADD CONSTRAINT content_draft_requests_author_post_fk
    FOREIGN KEY (author_id, post_id) REFERENCES content_posts (author_id, id);

CREATE TABLE content_author_purges (
    author_id UUID PRIMARY KEY,
    started_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
