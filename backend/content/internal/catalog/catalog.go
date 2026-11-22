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
	db        *sql.DB
	testSales bool
}

type Cursor struct {
	PublishedAt time.Time
	ID          uuid.UUID
}

type Filter struct {
	Viewer      uuid.UUID
	Kind        string
	Length      string
	Recommended bool
	Author      *uuid.UUID
	Limit       int
	Before      *Cursor
}

type FeedPosition struct {
	ID          uuid.UUID `json:"id"`
	PublishedAt time.Time `json:"published_at"`
}

type FeedPost struct {
	FeedPosition
	AuthorID               uuid.UUID  `json:"author_id"`
	Kind                   string     `json:"kind"`
	Title                  string     `json:"title"`
	RecommendationPosition time.Time  `json:"-"`
	DurationMillis         *int64     `json:"duration_ms,omitempty"`
	CoverMediaID           *uuid.UUID `json:"cover_media_id"`
	Likes                  int64      `json:"likes"`
	Views                  int64      `json:"views"`
	Liked                  bool       `json:"liked"`
	Favorited              bool       `json:"favorited"`
}

const feedEngagement = `COALESCE((SELECT likes FROM content_post_statistics WHERE post_id=p.id), 0),
    COALESCE((SELECT views FROM content_post_statistics WHERE post_id=p.id), 0),
    EXISTS (SELECT 1 FROM content_post_likes WHERE post_id=p.id AND viewer_id=$7),
    EXISTS (SELECT 1 FROM content_post_favorites WHERE post_id=p.id AND viewer_id=$7)`

func New(db *sql.DB) *Store {
	return &Store{db: db}
}

// ListPublic selects public posts. The caller checks the viewer and author accounts.
func (s *Store) ListPublic(ctx context.Context, filter Filter) ([]FeedPost, error) {
	if filter.Kind != "" && filter.Kind != "photo" && filter.Kind != "video" {
		return nil, ErrInvalidFilter
	}

	if filter.Length != "" && ((filter.Length != "short" && filter.Length != "long") || filter.Kind == "photo") {
		return nil, ErrInvalidFilter
	}

	if filter.Limit < 1 || filter.Limit > 100 || (filter.Author != nil && *filter.Author == uuid.Nil) {
		return nil, ErrInvalidFilter
	}

	if filter.Recommended {
		return s.listRecommendations(ctx, filter)
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

	const query = `SELECT p.id, p.published_at, p.author_id, p.media_kind, p.title,p.video_duration_ms,
            ` + postCoverMedia + `, ` + feedEngagement + `
        FROM content_posts p
        WHERE p.status = 'published' AND p.hidden_by_case IS NULL AND p.visibility = 'public'
            AND NOT EXISTS (SELECT 1 FROM content_author_purges a WHERE a.author_id = p.author_id)
            AND ($1::text = '' OR media_kind = $1)
            AND ($2::uuid IS NULL OR p.author_id = $2)
            AND ($3::timestamptz IS NULL OR (published_at, id) < ($3, $4::uuid))
        AND ($6::text='' OR (p.media_kind='video' AND CASE $6
                  WHEN 'short' THEN p.video_duration_ms<=60000
                  WHEN 'long' THEN p.video_duration_ms>60000 END))
        ORDER BY published_at DESC, id DESC LIMIT $5`

	rows, err := s.db.QueryContext(ctx, query, filter.Kind, author, beforeTime, beforeID, filter.Limit, filter.Length, filter.Viewer)

	if err != nil {
		return nil, fmt.Errorf("list public posts: %w", err)
	}

	defer rows.Close()

	return readFeedPosts(rows, filter.Limit, false)
}

func readFeedPosts(rows *sql.Rows, limit int, recommended bool) ([]FeedPost, error) {
	posts := make([]FeedPost, 0, limit)

	for rows.Next() {
		var post FeedPost
		var cover uuid.NullUUID

		fields := []any{&post.ID, &post.PublishedAt, &post.AuthorID, &post.Kind, &post.Title, &post.DurationMillis, &cover, &post.Likes, &post.Views, &post.Liked, &post.Favorited}
		if recommended {
			fields = append(fields, &post.RecommendationPosition)
		}
		if err := rows.Scan(fields...); err != nil {
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
