package catalog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

type PublicationDraft struct {
	Kind     string
	MediaIDs []string
}

func (s *Store) DraftForPublication(ctx context.Context, author, id uuid.UUID, revision int64) (PublicationDraft, error) {
	const query = `SELECT media_kind, revision, status,
		ARRAY(SELECT media_id::text FROM content_post_media WHERE post_id = p.id ORDER BY position)
		FROM content_posts p WHERE id = $1 AND author_id = $2
			AND ((status = 'draft' AND visibility = 'private') OR status = 'published')`

	var draft PublicationDraft
	var storedRevision int64
	var status string
	err := s.db.QueryRowContext(ctx, query, id, author).Scan(&draft.Kind, &storedRevision, &status, pq.Array(&draft.MediaIDs))

	if errors.Is(err, sql.ErrNoRows) {
		return PublicationDraft{}, ErrDraftNotFound
	}
	if err != nil {
		return PublicationDraft{}, fmt.Errorf("load publication draft: %w", err)
	}
	if status == "draft" && storedRevision != revision || status == "published" && storedRevision != revision+1 {
		return PublicationDraft{}, ErrDraftVersionConflict
	}
	if len(draft.MediaIDs) == 0 || len(draft.MediaIDs) > 16 {
		return PublicationDraft{}, ErrInvalidDraft
	}

	return draft, nil
}

func (s *Store) PublishPost(ctx context.Context, author, id uuid.UUID, revision int64, visibility string, duration *int64) (int64, error) {
	var next int64
	err := s.db.QueryRowContext(ctx, `SELECT public.content_publish_post_duration($1, $2, $3, $4,$5)`, author, id, revision, visibility, duration).Scan(&next)
	if err != nil {
		return 0, fmt.Errorf("publish draft: %w", err)
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
