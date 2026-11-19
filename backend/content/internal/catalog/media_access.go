package catalog

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

func (s *Store) AllowsPostMedia(ctx context.Context, post, media, owner, viewer uuid.UUID) (bool, error) {
	const query = `SELECT EXISTS (
		SELECT 1 FROM content_posts p
		JOIN content_post_media m ON m.post_id = p.id AND m.media_id = $2
		WHERE p.id = $1 AND p.author_id = $3 AND p.status = 'published'
			AND (p.visibility = 'public' OR p.author_id = $4)
			AND NOT EXISTS (SELECT 1 FROM content_author_purges WHERE author_id = p.author_id)
	)`

	var allowed bool

	if err := s.db.QueryRowContext(ctx, query, post, media, owner, viewer).Scan(&allowed); err != nil {
		return false, fmt.Errorf("check post attachment: %w", err)
	}

	return allowed, nil
}
