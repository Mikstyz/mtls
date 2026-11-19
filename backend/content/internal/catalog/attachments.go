package catalog

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

func (s *Store) SetDraftMedia(ctx context.Context, author, draft uuid.UUID, revision int64, attachments []uuid.UUID) (int64, error) {
	ids := make([]string, len(attachments))
	for i, id := range attachments {
		ids[i] = id.String()
	}

	var next int64
	err := s.db.QueryRowContext(ctx, `SELECT public.content_set_draft_media($1, $2, $3, $4::uuid[])`, author, draft, revision, pq.Array(ids)).Scan(&next)

	if err != nil {
		return 0, fmt.Errorf("replace draft attachments: %w", err)
	}

	switch next {
	case -1:
		return 0, ErrDraftNotFound
	case 0:
		return 0, ErrDraftVersionConflict
	default:
		return next, nil
	}
}
