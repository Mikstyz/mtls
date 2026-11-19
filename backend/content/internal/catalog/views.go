package catalog

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

func (s *Store) CountPostView(ctx context.Context, post, media, viewer uuid.UUID, day int32) error {
	const query = `SELECT public.content_count_post_view($1, $2, $3, $4)`

	if _, err := s.db.ExecContext(ctx, query, post, media, viewer, day); err != nil {
		return fmt.Errorf("record post view: %w", err)
	}

	return nil
}
