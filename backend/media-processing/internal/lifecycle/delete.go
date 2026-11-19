package lifecycle

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// CheckDeleting confirms ownership and that new processing has been closed.
func (s *Store) CheckDeleting(ctx context.Context, owner, id uuid.UUID) error {
	if owner == uuid.Nil || id == uuid.Nil {
		return ErrInvalid
	}

	const query = `SELECT EXISTS (SELECT 1 FROM media_assets
		WHERE id = $1 AND owner_id = $2 AND state = 'deleting')`

	var allowed bool

	if err := s.db.QueryRowContext(ctx, query, id, owner).Scan(&allowed); err != nil {
		return fmt.Errorf("check media deletion: %w", err)
	}

	if !allowed {
		return ErrConflict
	}

	return nil
}

// NextDeletion returns one due deletion. Deletion operations are idempotent.
func (s *Store) NextDeletion(ctx context.Context) (uuid.UUID, uuid.UUID, error) {
	const query = `SELECT owner_id, id FROM media_assets
		WHERE state = 'deleting' AND files_removed_at IS NULL AND delete_retry_at <= CURRENT_TIMESTAMP
		ORDER BY delete_retry_at, id LIMIT 1`

	var owner, id uuid.UUID
	err := s.db.QueryRowContext(ctx, query).Scan(&owner, &id)

	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, uuid.Nil, ErrNotFound
	}

	return owner, id, err
}

func (s *Store) DeferDeletion(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `UPDATE media_assets SET delete_retry_at = CURRENT_TIMESTAMP + INTERVAL '15 seconds'
		WHERE id = $1 AND state = 'deleting' AND files_removed_at IS NULL`, id)
	return err
}

func (s *Store) FinishDeletion(ctx context.Context, owner, id uuid.UUID) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Reservation also locks the quota before touching an asset.
	if _, err := tx.ExecContext(ctx, `SELECT assets FROM public.media_lock_usage()`); err != nil {
		return err
	}

	const query = `UPDATE media_assets SET files_removed_at = COALESCE(files_removed_at, CURRENT_TIMESTAMP)
		WHERE id = $1 AND owner_id = $2 AND state = 'deleting' RETURNING id`

	var removed uuid.UUID
	err = tx.QueryRowContext(ctx, query, id, owner).Scan(&removed)

	if errors.Is(err, sql.ErrNoRows) {
		return ErrConflict
	}

	if err != nil {
		return err
	}

	return tx.Commit()
}
