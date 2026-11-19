package catalog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"

	"github.com/google/uuid"
)

var (
	ErrDraftNotFound        = errors.New("draft not found")
	ErrDraftVersionConflict = errors.New("draft revision conflict")
)

// EditDraft uses the revision returned by ListDrafts to prevent lost updates.
func (s *Store) EditDraft(ctx context.Context, author, id uuid.UUID, revision int64, title, description string) (int64, error) {
	if author == uuid.Nil || id == uuid.Nil || revision < 1 || revision == math.MaxInt64 || !validDraftText(title, description) {
		return 0, ErrInvalidDraft
	}

	const query = `UPDATE content_posts
		SET title = $4, description = $5, revision = revision + 1
		WHERE author_id = $1 AND id = $2 AND revision = $3
			AND status = 'draft' AND visibility = 'private'
		RETURNING revision`

	var next int64
	err := s.db.QueryRowContext(ctx, query, author, id, revision, title, description).Scan(&next)

	if err == nil {
		return next, nil
	}

	if !errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("edit draft: %w", err)
	}

	var exists bool
	err = s.db.QueryRowContext(ctx, `SELECT EXISTS (
		SELECT 1 FROM content_posts WHERE author_id = $1 AND id = $2 AND status = 'draft' AND visibility = 'private'
	)`, author, id).Scan(&exists)

	if err != nil {
		return 0, fmt.Errorf("check draft: %w", err)
	}

	if exists {
		return 0, ErrDraftVersionConflict
	}

	return 0, ErrDraftNotFound
}
