package lifecycle

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ClaimNextPhoto gives one uploaded photo to one worker, including expired leases.
func (s *Store) ClaimNextPhoto(ctx context.Context, duration time.Duration) (uuid.UUID, uuid.UUID, error) {
	if ctx == nil || duration < time.Second || duration > 30*time.Minute || duration%time.Second != 0 {
		return uuid.Nil, uuid.Nil, ErrInvalid
	}

	token, err := uuid.NewRandom()

	if err != nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("generate processing lease: %w", err)
	}

	const query = `WITH candidate AS (
		SELECT a.id FROM media_assets a JOIN media_uploads u ON u.asset_id = a.id
		WHERE a.kind = 'photo' AND u.uploaded AND u.byte_size <= 33554432
			AND a.photo_attempts < 5 AND a.photo_retry_at <= clock_timestamp()
			AND (a.state = 'reserved' OR (a.state = 'processing' AND a.lease_until <= clock_timestamp()))
		ORDER BY a.created_at, a.id
		FOR UPDATE OF a SKIP LOCKED LIMIT 1
	)
	UPDATE media_assets a SET state = 'processing', lease_token = $1, photo_attempts = a.photo_attempts + 1,
		lease_until = clock_timestamp() + $2 * INTERVAL '1 second'
	FROM candidate WHERE a.id = candidate.id RETURNING a.id`

	var id uuid.UUID
	err = s.db.QueryRowContext(ctx, query, token, int64(duration/time.Second)).Scan(&id)

	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, uuid.Nil, ErrNotFound
	}

	if err != nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("claim photo processing: %w", err)
	}

	return id, token, nil
}

// FailPhoto releases the current lease and schedules a bounded retry. A job
// that has used five attempts remains recorded for later inspection or deletion.
func (s *Store) FailPhoto(ctx context.Context, id, lease uuid.UUID, delay time.Duration) error {
	if ctx == nil || id == uuid.Nil || lease == uuid.Nil || delay < time.Second || delay > 24*time.Hour || delay%time.Second != 0 {
		return ErrInvalid
	}

	const query = `UPDATE media_assets SET state = 'reserved', lease_token = NULL, lease_until = NULL,
		photo_retry_at = clock_timestamp() + $3 * INTERVAL '1 second'
		WHERE id = $1 AND kind = 'photo' AND state = 'processing' AND lease_token = $2
			AND lease_until > clock_timestamp() RETURNING id`

	var updated uuid.UUID
	err := s.db.QueryRowContext(ctx, query, id, lease, int64(delay/time.Second)).Scan(&updated)

	if errors.Is(err, sql.ErrNoRows) {
		return ErrConflict
	}

	if err != nil {
		return fmt.Errorf("schedule photo retry: %w", err)
	}

	return nil
}
