package catalog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

var ErrPostNotFound = errors.New("post not found")

type PublishedPost struct {
	ID               uuid.UUID  `json:"id"`
	AuthorID         uuid.UUID  `json:"author_id"`
	Kind             string     `json:"kind"`
	Title            string     `json:"title"`
	Description      string     `json:"description"`
	Visibility       string     `json:"visibility"`
	PublishedAt      time.Time  `json:"published_at"`
	Revision         int64      `json:"revision"`
	DurationMillis   *int64     `json:"duration_ms,omitempty"`
	PublishedEdition int64      `json:"published_edition"`
	CoverMediaID     *uuid.UUID `json:"cover_media_id,omitempty"`
	MediaIDs         []string   `json:"media_ids"`
	Likes            int64      `json:"likes"`
	Views            int64      `json:"views"`
	Liked            bool       `json:"liked"`
	Favorited        bool       `json:"favorited"`
}

func (s *Store) PublishedPostForViewer(ctx context.Context, viewer, id uuid.UUID) (PublishedPost, error) {
	const query = `SELECT p.id, p.author_id, p.media_kind, p.title, p.description, p.visibility,
		p.published_at, p.revision, p.video_duration_ms,COALESCE(p.published_edition,p.revision), ` + postCoverMedia + `,
		ARRAY(SELECT m.media_id::text FROM content_post_media m WHERE m.post_id = p.id ORDER BY m.position),
		COALESCE((SELECT likes FROM content_post_statistics WHERE post_id = p.id), 0),
		COALESCE((SELECT views FROM content_post_statistics WHERE post_id = p.id), 0),
		EXISTS (SELECT 1 FROM content_post_likes WHERE post_id = p.id AND viewer_id = $2),
		EXISTS (SELECT 1 FROM content_post_favorites WHERE post_id = p.id AND viewer_id = $2)
		FROM content_posts p
		WHERE p.id = $1 AND p.status = 'published' AND p.hidden_by_case IS NULL
			AND (p.visibility = 'public' OR p.author_id = $2 OR (p.visibility='private' AND $3 AND public.content_test_entitled(p.id,p.revision,$2)))
			AND NOT EXISTS (SELECT 1 FROM content_author_purges WHERE author_id = p.author_id)`

	var post PublishedPost
	var cover uuid.NullUUID
	err := s.db.QueryRowContext(ctx, query, id, viewer, s.testSales).Scan(
		&post.ID, &post.AuthorID, &post.Kind, &post.Title, &post.Description,
		&post.Visibility, &post.PublishedAt, &post.Revision, &post.DurationMillis, &post.PublishedEdition, &cover, pq.Array(&post.MediaIDs),
		&post.Likes, &post.Views, &post.Liked, &post.Favorited,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return PublishedPost{}, ErrPostNotFound
	}
	if err != nil {
		return PublishedPost{}, fmt.Errorf("load published post: %w", err)
	}

	if cover.Valid {
		post.CoverMediaID = &cover.UUID
	}

	return post, nil
}

func (s *Store) ChangeAuthorRemoval(ctx context.Context, author, id uuid.UUID, revision int64, restore bool) (int64, error) {
	const query = `SELECT public.content_change_author_removal($1, $2, $3, $4)`

	var next int64
	err := s.db.QueryRowContext(ctx, query, author, id, revision, restore).Scan(&next)

	if err != nil {
		return 0, fmt.Errorf("change author removal: %w", err)
	}

	switch next {
	case -1:
		return 0, ErrPostNotFound
	case 0:
		return 0, ErrDraftVersionConflict
	default:
		return next, nil
	}
}
