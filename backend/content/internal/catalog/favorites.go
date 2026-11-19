package catalog

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type Favorite struct {
	FeedPost
	AddedAt time.Time `json:"added_at"`
}

type FavoriteCursor struct {
	ID      uuid.UUID
	AddedAt time.Time
}

func (s *Store) ListFavorites(ctx context.Context, viewer uuid.UUID, limit int, before *FavoriteCursor) ([]Favorite, error) {
	if viewer == uuid.Nil || limit < 1 || limit > 41 {
		return nil, ErrInvalidFilter
	}

	var beforeTime, beforeID any
	if before != nil {
		beforeTime, beforeID = before.AddedAt, before.ID
	}

	const query = `SELECT p.id, p.author_id, p.media_kind, p.title, p.published_at, f.added_at,
		(SELECT m.media_id FROM content_post_media m WHERE m.post_id = p.id ORDER BY m.position LIMIT 1)
		FROM content_post_favorites f JOIN content_posts p ON p.id = f.post_id
		WHERE f.viewer_id = $1 AND p.status = 'published'
			AND (p.visibility = 'public' OR p.author_id = $1)
			AND NOT EXISTS (SELECT 1 FROM content_author_purges a WHERE a.author_id IN ($1, p.author_id))
			AND ($2::timestamptz IS NULL OR (f.added_at, f.post_id) < ($2, $3::uuid))
		ORDER BY f.added_at DESC, f.post_id DESC LIMIT $4`

	rows, err := s.db.QueryContext(ctx, query, viewer, beforeTime, beforeID, limit)
	if err != nil {
		return nil, fmt.Errorf("list favorites: %w", err)
	}
	defer rows.Close()

	favorites := make([]Favorite, 0, limit)
	for rows.Next() {
		var favorite Favorite
		var cover uuid.NullUUID
		if err := rows.Scan(&favorite.ID, &favorite.AuthorID, &favorite.Kind, &favorite.Title,
			&favorite.PublishedAt, &favorite.AddedAt, &cover); err != nil {
			return nil, fmt.Errorf("read favorite: %w", err)
		}
		if cover.Valid {
			favorite.CoverMediaID = &cover.UUID
		}

		favorites = append(favorites, favorite)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read favorites: %w", err)
	}

	return favorites, nil
}
