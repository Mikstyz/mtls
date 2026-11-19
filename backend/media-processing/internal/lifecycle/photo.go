package lifecycle

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// CheckPhotoLease permits only the current worker or an exact completion replay.
func (s *Store) CheckPhotoLease(ctx context.Context, id, lease uuid.UUID) error {
	if id == uuid.Nil || lease == uuid.Nil {
		return ErrInvalid
	}

	const query = `SELECT EXISTS (SELECT 1 FROM media_assets
		WHERE id = $1 AND kind = 'photo' AND (
			(state = 'processing' AND lease_token = $2 AND lease_until > clock_timestamp())
			OR (state = 'processed' AND processed_lease_token = $2)
		))`

	var allowed bool

	if err := s.db.QueryRowContext(ctx, query, id, lease).Scan(&allowed); err != nil {
		return fmt.Errorf("check photo processing lease: %w", err)
	}

	if !allowed {
		return ErrConflict
	}

	return nil
}

// MarkPhotoProcessed records a worker's complete manifest; it does not grant access.
func (s *Store) MarkPhotoProcessed(ctx context.Context, id, lease uuid.UUID, variants []Variant) error {
	if id == uuid.Nil || lease == uuid.Nil || !validPhotoVariants(variants) {
		return ErrInvalid
	}

	tx, err := s.db.BeginTx(ctx, nil)

	if err != nil {
		return fmt.Errorf("begin photo completion: %w", err)
	}

	defer tx.Rollback()

	const update = `UPDATE media_assets SET state = 'processed', processed_lease_token = $2,
			lease_token = NULL, lease_until = NULL
		WHERE id = $1 AND kind = 'photo' AND state = 'processing'
			AND lease_token = $2 AND lease_until > clock_timestamp()
		RETURNING id`

	var updated uuid.UUID
	err = tx.QueryRowContext(ctx, update, id, lease).Scan(&updated)

	if errors.Is(err, sql.ErrNoRows) {
		return verifyPhotoReplay(ctx, tx, id, lease, variants)
	}

	if err != nil {
		return fmt.Errorf("finish photo processing: %w", err)
	}

	for _, variant := range variants {
		_, err := tx.ExecContext(ctx, `INSERT INTO media_variants (asset_id, name, byte_size, sha256) VALUES ($1, $2, $3, $4)`, id, variant.Name, variant.Size, variant.SHA256[:])

		if err != nil {
			return fmt.Errorf("record photo variant: %w", err)
		}
	}

	if _, err := tx.ExecContext(ctx, `INSERT INTO media_ready_events (asset_id) VALUES ($1)`, id); err != nil {
		return fmt.Errorf("record ready event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit photo processing: %w", err)
	}

	return nil
}

func verifyPhotoReplay(ctx context.Context, tx *sql.Tx, id, lease uuid.UUID, expected []Variant) error {
	const lookup = `SELECT id FROM media_assets
		WHERE id = $1 AND kind = 'photo' AND state = 'processed' AND processed_lease_token = $2
		FOR UPDATE`

	var found uuid.UUID
	err := tx.QueryRowContext(ctx, lookup, id, lease).Scan(&found)

	if errors.Is(err, sql.ErrNoRows) {
		return ErrConflict
	}

	if err != nil {
		return fmt.Errorf("check photo replay: %w", err)
	}

	rows, err := tx.QueryContext(ctx, `SELECT name, byte_size, sha256 FROM media_variants WHERE asset_id = $1`, id)

	if err != nil {
		return fmt.Errorf("read photo manifest: %w", err)
	}

	defer rows.Close()
	remaining := make(map[string]Variant, len(expected))

	for _, variant := range expected {
		remaining[variant.Name] = variant
	}

	for rows.Next() {
		var name string
		var size int64
		var digest []byte

		if err := rows.Scan(&name, &size, &digest); err != nil {
			return fmt.Errorf("read photo manifest: %w", err)
		}

		variant, ok := remaining[name]

		if !ok || variant.Size != size || !bytes.Equal(variant.SHA256[:], digest) {
			return ErrConflict
		}

		delete(remaining, name)
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("read photo manifest: %w", err)
	}

	if err := rows.Close(); err != nil {
		return fmt.Errorf("close photo manifest: %w", err)
	}

	if len(remaining) != 0 {
		return ErrConflict
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit photo replay: %w", err)
	}

	return nil
}

func validPhotoVariants(variants []Variant) bool {
	if len(variants) != 2 {
		return false
	}

	names := make(map[string]bool, 2)

	for _, variant := range variants {
		if variant.Size <= 0 || variant.Size > 32<<20 || names[variant.Name] {
			return false
		}

		names[variant.Name] = true
	}

	return (names["original.jpg"] && names["preview.jpg"]) ||
		(names["original.png"] && names["preview.png"])
}
