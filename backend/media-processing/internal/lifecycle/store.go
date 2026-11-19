package lifecycle

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalid            = errors.New("invalid media operation")
	ErrConflict           = errors.New("media state conflict")
	ErrNotFound           = errors.New("media asset not found")
	ErrQuota              = errors.New("media quota exceeded")
	ErrQuotaConfiguration = errors.New("media quota configuration mismatch")
)

type Store struct {
	db *sql.DB
}

type Asset struct {
	ID    uuid.UUID
	State string
}

type Variant struct {
	Name   string
	Size   int64
	SHA256 [32]byte
}

func New(db *sql.DB) *Store {
	return &Store{db: db}
}

// Claim leases a reservation or an expired processing attempt to one worker.
func (s *Store) Claim(ctx context.Context, id uuid.UUID, duration time.Duration) (uuid.UUID, error) {
	if id == uuid.Nil || duration < time.Second || duration > 30*time.Minute || duration%time.Second != 0 {
		return uuid.Nil, ErrInvalid
	}

	token, err := uuid.NewRandom()

	if err != nil {
		return uuid.Nil, fmt.Errorf("generate processing lease: %w", err)
	}

	const query = `UPDATE media_assets
		SET state = 'processing', lease_token = $2, lease_until = clock_timestamp() + $3 * INTERVAL '1 second',
			photo_attempts = photo_attempts + CASE WHEN kind = 'photo' THEN 1 ELSE 0 END
		WHERE id = $1 AND EXISTS (SELECT 1 FROM media_uploads WHERE asset_id = $1 AND uploaded)
			AND (kind <> 'photo' OR (photo_attempts < 5 AND photo_retry_at <= clock_timestamp()))
			AND (state = 'reserved' OR (state = 'processing' AND lease_until <= clock_timestamp()))
		RETURNING id`

	var claimed uuid.UUID
	err = s.db.QueryRowContext(ctx, query, id, token, int64(duration/time.Second)).Scan(&claimed)

	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, ErrConflict
	}

	if err != nil {
		return uuid.Nil, fmt.Errorf("claim media processing: %w", err)
	}

	return token, nil
}

// BeginDelete closes the processing state but retains metadata for physical cleanup.
func (s *Store) BeginDelete(ctx context.Context, owner, id uuid.UUID) error {
	if owner == uuid.Nil || id == uuid.Nil {
		return ErrInvalid
	}

	const query = `UPDATE media_assets SET state = 'deleting', lease_token = NULL, lease_until = NULL
		WHERE id = $1 AND owner_id = $2`

	result, err := s.db.ExecContext(ctx, query, id, owner)

	if err != nil {
		return fmt.Errorf("begin media deletion: %w", err)
	}

	count, err := result.RowsAffected()

	if err != nil {
		return fmt.Errorf("check media deletion: %w", err)
	}

	if count == 0 {
		return ErrNotFound
	}

	return nil
}
