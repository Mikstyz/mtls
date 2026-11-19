CREATE TABLE content_draft_requests (
    author_id UUID NOT NULL,
    request_id UUID NOT NULL,
    post_id UUID NOT NULL REFERENCES content_posts (id),
    media_kind TEXT NOT NULL CHECK (media_kind IN ('video', 'photo')),
    title TEXT NOT NULL CHECK (char_length(title) <= 200),
    description TEXT NOT NULL CHECK (char_length(description) <= 4096),
    PRIMARY KEY (author_id, request_id),
    UNIQUE (post_id)
);
