package lifecycle

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

const uploadState = `CASE
	WHEN a.files_removed_at IS NOT NULL THEN 'deleted'
	WHEN a.state = 'deleting' THEN 'deleting'
	WHEN a.state = 'processed' THEN 'processed'
	WHEN a.processing_attempts >= 5 AND
		(a.state = 'reserved' OR a.lease_until <= statement_timestamp()) THEN 'failed'
	WHEN a.state = 'processing' THEN 'processing'
	WHEN u.uploaded THEN 'uploaded'
	ELSE 'reserved'
END`

type UploadPosition struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
}

type UploadHistoryItem struct {
	UploadPosition
	Kind      string     `json:"kind"`
	State     string     `json:"state"`
	Size      *int64     `json:"size,omitempty"`
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
}

const UploadHistoryPageSize = 20

func (s *Store) UploadHistory(ctx context.Context, owner uuid.UUID, before *UploadPosition) ([]UploadHistoryItem, error) {
	if owner == uuid.Nil || before != nil && (before.ID == uuid.Nil || before.CreatedAt.IsZero()) {
		return nil, ErrInvalid
	}

	var instant, id any
	if before != nil {
		instant, id = before.CreatedAt, before.ID
	}

	const query = `SELECT a.id,a.created_at,a.kind,` + uploadState + `,u.byte_size,a.files_removed_at
		FROM media_assets a LEFT JOIN media_uploads u ON u.asset_id=a.id
		WHERE a.owner_id=$1 AND ($2::timestamptz IS NULL OR (a.created_at,a.id)<($2,$3::uuid))
		ORDER BY a.created_at DESC,a.id DESC LIMIT $4`

	rows, err := s.db.QueryContext(ctx, query, owner, instant, id, UploadHistoryPageSize+1)
	if err != nil {
		return nil, fmt.Errorf("list upload history: %w", err)
	}
	defer rows.Close()

	items := make([]UploadHistoryItem, 0, UploadHistoryPageSize+1)
	for rows.Next() {
		var item UploadHistoryItem
		if err := rows.Scan(&item.ID, &item.CreatedAt, &item.Kind, &item.State, &item.Size, &item.DeletedAt); err != nil {
			return nil, fmt.Errorf("read upload history: %w", err)
		}
		items = append(items, item)
	}

	return items, rows.Err()
}
