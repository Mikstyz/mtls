package catalog

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

var ErrInvalidDraftFilter = errors.New("invalid draft filter")

type DraftCursor struct {
	CreatedAt time.Time
	ID        uuid.UUID
}

type DraftSummary struct {
	ID                uuid.UUID
	Kind              string
	Title             string
	Description       string
	CreatedAt         time.Time
	Revision          int64
	MediaIDs          []string
	PublishAt         *time.Time
	PlannedVisibility *string
}

// ListDrafts returns only the authenticated author's private drafts.
func (s *Store) ListDrafts(ctx context.Context, author uuid.UUID, limit int, before *DraftCursor) ([]DraftSummary, error) {
	if author == uuid.Nil || limit < 1 || limit > 100 {
		return nil, ErrInvalidDraftFilter
	}

	var beforeTime, beforeID any

	if before != nil {
		if before.CreatedAt.IsZero() || before.ID == uuid.Nil {
			return nil, ErrInvalidDraftFilter
		}

		beforeTime, beforeID = before.CreatedAt, before.ID
	}

	const query = `SELECT id, media_kind, title, description, created_at, revision,
 ARRAY(SELECT m.media_id::text FROM content_post_media m WHERE m.post_id = content_posts.id ORDER BY m.position),
 (SELECT publish_at FROM content_scheduled_posts WHERE post_id=content_posts.id),
 (SELECT visibility FROM content_scheduled_posts WHERE post_id=content_posts.id)
		FROM content_posts
		WHERE author_id = $1 AND status = 'draft' AND visibility = 'private'
			AND ($2::timestamptz IS NULL OR (created_at, id) < ($2, $3::uuid))
		ORDER BY created_at DESC, id DESC LIMIT $4`

	rows, err := s.db.QueryContext(ctx, query, author, beforeTime, beforeID, limit)

	if err != nil {
		return nil, fmt.Errorf("list drafts: %w", err)
	}

	defer rows.Close()
	drafts := make([]DraftSummary, 0, limit)

	for rows.Next() {
		var draft DraftSummary

		if err := rows.Scan(&draft.ID, &draft.Kind, &draft.Title, &draft.Description, &draft.CreatedAt, &draft.Revision, pq.Array(&draft.MediaIDs), &draft.PublishAt, &draft.PlannedVisibility); err != nil {
			return nil, fmt.Errorf("read draft: %w", err)
		}

		drafts = append(drafts, draft)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read drafts: %w", err)
	}

	return drafts, nil
}
