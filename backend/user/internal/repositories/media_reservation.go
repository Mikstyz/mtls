package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

var ErrMediaConflict = errors.New("media reservation conflict")

// ReserveMedia establishes private, not-ready ownership without granting access.
// The caller must authenticate the owner and the media-processing service.
func (r *userRepo) ReserveMedia(ctx context.Context, owner, media uuid.UUID) error {
	if owner == uuid.Nil || media == uuid.Nil {
		return ErrMediaConflict
	}

	tx, err := r.db.BeginTx(ctx, nil)

	if err != nil {
		return fmt.Errorf("begin media reservation: %w", err)
	}

	defer tx.Rollback()

	if err := lockUserLifecycle(ctx, tx, owner); err != nil {
		return err
	}

	const checkOwner = `SELECT EXISTS (SELECT 1 FROM users WHERE id = $1)
		AND NOT EXISTS (SELECT 1 FROM content_purge_events WHERE user_id = $1)`

	var allowed bool

	if err := tx.QueryRowContext(ctx, checkOwner, owner).Scan(&allowed); err != nil {
		return fmt.Errorf("check media owner: %w", err)
	}

	if !allowed {
		return ErrMediaConflict
	}

	const reserve = `INSERT INTO media_permissions (media_id, owner_id)
		VALUES ($1, $2) ON CONFLICT (media_id) DO NOTHING`

	if _, err := tx.ExecContext(ctx, reserve, media, owner); err != nil {
		return fmt.Errorf("reserve media policy: %w", err)
	}

	var actual uuid.UUID
	err = tx.QueryRowContext(ctx, `SELECT owner_id FROM media_permissions WHERE media_id = $1 AND revoked_at IS NULL`, media).Scan(&actual)

	if errors.Is(err, sql.ErrNoRows) {
		return ErrMediaConflict
	}

	if err != nil {
		return fmt.Errorf("read media reservation: %w", err)
	}

	if actual != owner {
		return ErrMediaConflict
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit media reservation: %w", err)
	}

	return nil
}

// MarkMediaReady changes an existing policy's readiness without expanding visibility.
func (r *userRepo) MarkMediaReady(ctx context.Context, owner, media uuid.UUID, kind string) error {
	const query = `UPDATE media_permissions SET ready = TRUE, media_kind = $3
		WHERE media_id = $1 AND owner_id = $2 AND revoked_at IS NULL
		AND (media_kind IS NULL OR media_kind = $3) RETURNING media_id`

	var id uuid.UUID
	err := r.db.QueryRowContext(ctx, query, media, owner, kind).Scan(&id)

	if errors.Is(err, sql.ErrNoRows) {
		return ErrMediaConflict
	}

	if err != nil {
		return fmt.Errorf("mark media ready: %w", err)
	}

	return nil
}

// RevokeMedia closes access permanently for this asset ID. A tombstone also
// protects against late reservation and readiness requests.
func (r *userRepo) RevokeMedia(ctx context.Context, owner, media uuid.UUID) error {
	if owner == uuid.Nil || media == uuid.Nil {
		return ErrMediaConflict
	}

	const query = `INSERT INTO media_permissions (media_id, owner_id, revoked_at)
		VALUES ($1, $2, CURRENT_TIMESTAMP)
		ON CONFLICT (media_id) DO UPDATE
		SET revoked_at = COALESCE(media_permissions.revoked_at, EXCLUDED.revoked_at),
		    ready = FALSE, visibility = 'private'
		WHERE media_permissions.owner_id = EXCLUDED.owner_id
		RETURNING media_id`

	var id uuid.UUID
	err := r.db.QueryRowContext(ctx, query, media, owner).Scan(&id)

	if errors.Is(err, sql.ErrNoRows) {
		return ErrMediaConflict
	}

	if err != nil {
		return fmt.Errorf("revoke media policy: %w", err)
	}

	return nil
}
