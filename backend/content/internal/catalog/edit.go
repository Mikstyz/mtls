package catalog

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/google/uuid"
)

var (
	ErrDraftNotFound        = errors.New("draft not found")
	ErrDraftVersionConflict = errors.New("draft revision conflict")
)

// EditDraft uses the revision returned by ListDrafts to prevent lost updates.
func (s *Store) EditDraft(ctx context.Context, author, id uuid.UUID, revision int64, title, description string) (int64, error) {
	return s.editPost(ctx, author, id, revision, title, description, "draft")
}

func (s *Store) EditPublishedPost(ctx context.Context, author, id uuid.UUID, revision int64, title, description string) (int64, error) {
	if strings.TrimSpace(title) == "" {
		return 0, ErrInvalidDraft
	}
	return s.editPost(ctx, author, id, revision, title, description, "published")
}

func (s *Store) editPost(ctx context.Context, author, id uuid.UUID, revision int64, title, description, status string) (int64, error) {
	if author == uuid.Nil || id == uuid.Nil || revision < 1 || revision == math.MaxInt64 || !validDraftText(title, description) {
		return 0, ErrInvalidDraft
	}

	const query = `SELECT public.content_edit_post($1,$2,$3,$4,$5,$6)`
	var next int64
	if err := s.db.QueryRowContext(ctx, query, author, id, revision, title, description, status).Scan(&next); err != nil {
		return 0, fmt.Errorf("edit post: %w", err)
	}

	switch next {
	case -2:
		return 0, ErrInvalidDraft
	case -1:
		return 0, ErrDraftNotFound
	case 0:
		return 0, ErrDraftVersionConflict
	default:
		return next, nil
	}
}
