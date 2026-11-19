package lifecycle

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// Quota limits original upload reservations owned by one account.
type Quota struct {
	MaxAssets       int64
	MaxBytes        int64
	GlobalMaxAssets int64
	GlobalMaxBytes  int64
}

// ReserveUpload binds an idempotency key to the owner, kind, size and digest.
// All reservation writers must use this method and its per-owner database lock.
func (s *Store) ReserveUpload(ctx context.Context, owner, request uuid.UUID, kind string, size int64, digest [32]byte, quota Quota) (Asset, error) {
	if ctx == nil || owner == uuid.Nil || request == uuid.Nil || (kind != "photo" && kind != "video") || size < 1 || size > 1<<40 || (kind == "photo" && size > 32<<20) || !quota.valid() {
		return Asset{}, ErrInvalid
	}

	id, err := uuid.NewRandom()

	if err != nil {
		return Asset{}, fmt.Errorf("generate media ID: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)

	if err != nil {
		return Asset{}, fmt.Errorf("begin upload reservation: %w", err)
	}

	defer tx.Rollback()

	usage, err := lockGlobalQuota(ctx, tx, quota)

	if err != nil {
		return Asset{}, err
	}

	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "media-quota:"+owner.String()); err != nil {
		return Asset{}, fmt.Errorf("lock media quota: %w", err)
	}

	const lookup = `SELECT a.id, a.state, a.kind, u.byte_size, u.sha256
		FROM media_assets a LEFT JOIN media_uploads u ON u.asset_id = a.id
		WHERE a.owner_id = $1 AND a.request_id = $2 FOR UPDATE OF a`

	var asset Asset
	var existingKind string
	var existingSize sql.NullInt64
	var existingDigest []byte
	err = tx.QueryRowContext(ctx, lookup, owner, request).Scan(&asset.ID, &asset.State, &existingKind, &existingSize, &existingDigest)

	if err == nil {
		if !existingSize.Valid || existingKind != kind || existingSize.Int64 != size || !bytes.Equal(existingDigest, digest[:]) || asset.State == "deleting" {
			return Asset{}, ErrConflict
		}

		if err := tx.Commit(); err != nil {
			return Asset{}, fmt.Errorf("commit upload reservation replay: %w", err)
		}

		return asset, nil
	}

	if !errors.Is(err, sql.ErrNoRows) {
		return Asset{}, fmt.Errorf("read upload reservation: %w", err)
	}

	if usage.unknown != 0 {
		return Asset{}, ErrConflict
	}

	if usage.assets >= quota.GlobalMaxAssets || size > quota.GlobalMaxBytes || usage.bytes > quota.GlobalMaxBytes-size {
		return Asset{}, ErrQuota
	}

	const usageQuery = `SELECT COUNT(*), COALESCE(SUM(u.byte_size), 0), COUNT(*) FILTER (WHERE u.asset_id IS NULL)
		FROM media_assets a LEFT JOIN media_uploads u ON u.asset_id = a.id WHERE a.owner_id = $1 AND a.files_removed_at IS NULL`

	var count, used, unknown int64

	if err := tx.QueryRowContext(ctx, usageQuery, owner).Scan(&count, &used, &unknown); err != nil {
		return Asset{}, fmt.Errorf("check media quota: %w", err)
	}

	if unknown != 0 {
		return Asset{}, ErrConflict
	}

	if count >= quota.MaxAssets || size > quota.MaxBytes || used > quota.MaxBytes-size {
		return Asset{}, ErrQuota
	}

	const insert = `INSERT INTO media_assets (id, owner_id, request_id, kind) VALUES ($1, $2, $3, $4)`

	if _, err := tx.ExecContext(ctx, insert, id, owner, request, kind); err != nil {
		return Asset{}, fmt.Errorf("reserve upload: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `INSERT INTO media_uploads (asset_id, byte_size, sha256) VALUES ($1, $2, $3)`, id, size, digest[:]); err != nil {
		return Asset{}, fmt.Errorf("record upload metadata: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return Asset{}, fmt.Errorf("commit upload reservation: %w", err)
	}

	return Asset{ID: id, State: "reserved"}, nil
}

// CheckUpload checks a private reservation; caller must authenticate the owner separately.
func (s *Store) CheckUpload(ctx context.Context, owner, id uuid.UUID, size int64, digest [32]byte) error {
	if owner == uuid.Nil || id == uuid.Nil || size < 1 || size > 1<<40 {
		return ErrInvalid
	}
	const query = `SELECT EXISTS (SELECT 1 FROM media_assets a JOIN media_uploads u ON u.asset_id = a.id WHERE a.id = $1 AND a.owner_id = $2 AND a.state = 'reserved' AND u.byte_size = $3 AND u.sha256 = $4)`
	var allowed bool
	if err := s.db.QueryRowContext(ctx, query, id, owner, size, digest[:]).Scan(&allowed); err != nil {
		return fmt.Errorf("check upload reservation: %w", err)
	}
	if !allowed {
		return ErrConflict
	}
	return nil
}

// MarkUploaded records a verified durable file. Call only while holding the quarantine lock.
func (s *Store) MarkUploaded(ctx context.Context, owner, id uuid.UUID, size int64, digest [32]byte) error {
	if owner == uuid.Nil || id == uuid.Nil || size < 1 || size > 1<<40 {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin upload completion: %w", err)
	}
	defer tx.Rollback()

	const lock = `SELECT id FROM media_assets WHERE id = $1 AND owner_id = $2 AND state = 'reserved' FOR UPDATE`
	var found uuid.UUID
	err = tx.QueryRowContext(ctx, lock, id, owner).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrConflict
	}
	if err != nil {
		return fmt.Errorf("lock upload reservation: %w", err)
	}

	const query = `UPDATE media_uploads SET uploaded = TRUE
		WHERE asset_id = $1 AND byte_size = $2 AND sha256 = $3 RETURNING asset_id`
	err = tx.QueryRowContext(ctx, query, id, size, digest[:]).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrConflict
	}
	if err != nil {
		return fmt.Errorf("record completed upload: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit upload completion: %w", err)
	}
	return nil
}

// UploadComplete reports whether these exact upload metadata are already committed.
func (s *Store) UploadComplete(ctx context.Context, owner, id uuid.UUID, size int64, digest [32]byte) (bool, error) {
	if owner == uuid.Nil || id == uuid.Nil || size < 1 || size > 1<<40 {
		return false, ErrInvalid
	}

	const query = `SELECT u.uploaded FROM media_assets a JOIN media_uploads u ON u.asset_id = a.id
		WHERE a.id = $1 AND a.owner_id = $2 AND a.state <> 'deleting' AND u.byte_size = $3 AND u.sha256 = $4`

	var uploaded bool
	err := s.db.QueryRowContext(ctx, query, id, owner, size, digest[:]).Scan(&uploaded)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrConflict
	}
	if err != nil {
		return false, fmt.Errorf("check completed upload: %w", err)
	}

	return uploaded, nil
}

// UploadStatus reports processing progress to the owner, without exposing storage paths.
func (s *Store) UploadStatus(ctx context.Context, owner, id uuid.UUID) (string, error) {
	if owner == uuid.Nil || id == uuid.Nil {
		return "", ErrInvalid
	}

	const query = `SELECT CASE
		WHEN a.state = 'processed' THEN 'processed'
		WHEN a.kind = 'photo' AND a.photo_attempts >= 5 AND
			(a.state = 'reserved' OR a.lease_until <= clock_timestamp()) THEN 'failed'
		WHEN a.state = 'processing' THEN 'processing'
		WHEN u.uploaded THEN 'uploaded'
		ELSE 'reserved'
		END
		FROM media_assets a JOIN media_uploads u ON u.asset_id = a.id
		WHERE a.id = $1 AND a.owner_id = $2 AND a.state <> 'deleting'`

	var state string
	err := s.db.QueryRowContext(ctx, query, id, owner).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("read upload status: %w", err)
	}

	return state, nil
}
