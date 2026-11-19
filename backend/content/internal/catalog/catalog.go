package catalog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

var ErrInvalidFilter = errors.New("invalid catalog filter")

type Store struct {
	db *sql.DB
}

type Cursor struct {
	PublishedAt time.Time
	ID          uuid.UUID
}

type Filter struct {
	Kind   string
	Author *uuid.UUID
	Limit  int
	Before *Cursor
}

type FeedPosition struct {
	ID          uuid.UUID `json:"id"`
	PublishedAt time.Time `json:"published_at"`
}

type FeedPost struct {
	FeedPosition
	AuthorID     uuid.UUID  `json:"author_id"`
	Kind         string     `json:"kind"`
	Title        string     `json:"title"`
	CoverMediaID *uuid.UUID `json:"cover_media_id"`
}

func New(db *sql.DB) *Store {
	return &Store{db: db}
}

// ListPublic selects public posts. The caller checks the viewer and author accounts.
func (s *Store) ListPublic(ctx context.Context, filter Filter) ([]FeedPost, error) {
	if filter.Kind != "" && filter.Kind != "photo" && filter.Kind != "video" {
		return nil, ErrInvalidFilter
	}

	if filter.Limit < 1 || filter.Limit > 100 || (filter.Author != nil && *filter.Author == uuid.Nil) {
		return nil, ErrInvalidFilter
	}

	var author, beforeTime, beforeID any

	if filter.Author != nil {
		author = *filter.Author
	}

	if filter.Before != nil {
		if filter.Before.PublishedAt.IsZero() || filter.Before.ID == uuid.Nil {
			return nil, ErrInvalidFilter
		}

		beforeTime = filter.Before.PublishedAt
		beforeID = filter.Before.ID
	}

	const query = `SELECT p.id, p.published_at, p.author_id, p.media_kind, p.title,
            (SELECT m.media_id FROM content_post_media m WHERE m.post_id = p.id ORDER BY m.position LIMIT 1)
        FROM content_posts p
        WHERE p.status = 'published' AND p.visibility = 'public'
            AND NOT EXISTS (SELECT 1 FROM content_author_purges a WHERE a.author_id = p.author_id)
            AND ($1::text = '' OR media_kind = $1)
            AND ($2::uuid IS NULL OR p.author_id = $2)
            AND ($3::timestamptz IS NULL OR (published_at, id) < ($3, $4::uuid))
        ORDER BY published_at DESC, id DESC LIMIT $5`

	rows, err := s.db.QueryContext(ctx, query, filter.Kind, author, beforeTime, beforeID, filter.Limit)

	if err != nil {
		return nil, fmt.Errorf("list public posts: %w", err)
	}

	defer rows.Close()

	posts := make([]FeedPost, 0, filter.Limit)

	for rows.Next() {
		var post FeedPost
		var cover uuid.NullUUID

		if err := rows.Scan(&post.ID, &post.PublishedAt, &post.AuthorID, &post.Kind, &post.Title, &cover); err != nil {
			return nil, fmt.Errorf("read public post: %w", err)
		}
		if cover.Valid {
			post.CoverMediaID = &cover.UUID
		}

		posts = append(posts, post)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read public posts: %w", err)
	}

	return posts, nil
}
