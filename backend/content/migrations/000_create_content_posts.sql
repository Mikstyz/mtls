CREATE TABLE content_posts (
    id UUID PRIMARY KEY,
    author_id UUID NOT NULL,
    media_kind TEXT NOT NULL CHECK (media_kind IN ('video', 'photo')),
    title TEXT NOT NULL DEFAULT '' CHECK (char_length(title) <= 200),
    description TEXT NOT NULL DEFAULT '' CHECK (char_length(description) <= 4096),
    visibility TEXT NOT NULL DEFAULT 'private' CHECK (visibility IN ('private', 'public', 'paid')),
    status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'removed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    published_at TIMESTAMPTZ,
    CHECK (status <> 'published' OR published_at IS NOT NULL)
);

CREATE TABLE content_post_media (
    post_id UUID NOT NULL REFERENCES content_posts (id) ON DELETE CASCADE,
    media_id UUID NOT NULL,
    position INTEGER NOT NULL CHECK (position >= 0),
    PRIMARY KEY (post_id, media_id),
    UNIQUE (post_id, position)
);

CREATE INDEX content_posts_public_feed_idx ON content_posts (published_at DESC, id DESC)
    WHERE status = 'published' AND visibility = 'public';

CREATE INDEX content_posts_public_author_feed_idx ON content_posts (author_id, published_at DESC, id DESC)
    WHERE status = 'published' AND visibility = 'public';

CREATE INDEX content_posts_public_kind_feed_idx ON content_posts (media_kind, published_at DESC, id DESC)
    WHERE status = 'published' AND visibility = 'public';
