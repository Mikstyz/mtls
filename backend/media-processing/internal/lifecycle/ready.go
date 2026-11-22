package lifecycle

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

type ReadyEvent struct {
	AssetID        uuid.UUID
	OwnerID        uuid.UUID
	Kind           string
	DurationMillis *int64
}

func (s *Store) NextReadyEvent(ctx context.Context) (ReadyEvent, error) {
	const query = `SELECT e.asset_id, a.owner_id, a.kind, a.duration_ms FROM media_ready_events e
		JOIN media_assets a ON a.id = e.asset_id
		WHERE a.state = 'processed' AND e.available_at <= CURRENT_TIMESTAMP
		ORDER BY e.available_at, e.asset_id LIMIT 1`

	var event ReadyEvent
	err := s.db.QueryRowContext(ctx, query).Scan(&event.AssetID, &event.OwnerID, &event.Kind, &event.DurationMillis)

	if errors.Is(err, sql.ErrNoRows) {
		return ReadyEvent{}, ErrNotFound
	}

	if err != nil {
		return ReadyEvent{}, fmt.Errorf("read ready event: %w", err)
	}

	return event, nil
}

func (s *Store) AcknowledgeReady(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM media_ready_events WHERE asset_id = $1`, id)
	return err
}

func (s *Store) DeferReady(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `UPDATE media_ready_events
		SET available_at = CURRENT_TIMESTAMP + INTERVAL '10 seconds' WHERE asset_id = $1`, id)
	return err
}
