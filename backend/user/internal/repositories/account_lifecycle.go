package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

var ErrLifecycleConflict = errors.New("account lifecycle conflict")

// ApplyAccountLifecycle applies an authenticated, idempotent auth operation.
func (r *userRepo) ApplyAccountLifecycle(ctx context.Context, userID, operationID uuid.UUID, operation string, deletedAt time.Time) error {
	if userID == uuid.Nil || operationID == uuid.Nil || deletedAt.IsZero() {
		return ErrLifecycleConflict
	}

	switch operation {
	case "deleting", "restoring_owner", "restoring_moderator", "purging":
	default:
		return ErrLifecycleConflict
	}

	tx, err := r.db.BeginTx(ctx, nil)

	if err != nil {
		return fmt.Errorf("begin account lifecycle: %w", err)
	}

	defer tx.Rollback()

	if err := lockUserLifecycle(ctx, tx, userID); err != nil {
		return err
	}

	const record = `INSERT INTO account_lifecycle_operations (operation_id, user_id, operation, deleted_at)
		VALUES ($1, $2, $3, $4) ON CONFLICT (operation_id) DO NOTHING`

	result, err := tx.ExecContext(ctx, record, operationID, userID, operation, deletedAt)

	if err != nil {
		return fmt.Errorf("record account lifecycle: %w", err)
	}

	count, err := result.RowsAffected()

	if err != nil {
		return fmt.Errorf("record account lifecycle: %w", err)
	}

	if count == 0 {
		var originalUser uuid.UUID
		var originalOperation string
		var originalTime time.Time
		err := tx.QueryRowContext(ctx, `SELECT user_id, operation, deleted_at FROM account_lifecycle_operations WHERE operation_id = $1`, operationID).Scan(&originalUser, &originalOperation, &originalTime)

		if err != nil {
			return fmt.Errorf("lookup account lifecycle: %w", err)
		}

		if originalUser != userID || originalOperation != operation || !originalTime.Equal(deletedAt) {
			return ErrLifecycleConflict
		}

		return tx.Commit()
	}

	switch operation {
	case "deleting":
		const query = `WITH removed AS (
			DELETE FROM users WHERE id = $1 RETURNING id, nickname, created_at, last_online, presence_visibility, photo_quality, video_quality
		)
		INSERT INTO deleted_users (id, nickname, created_at, last_online, presence_visibility, photo_quality, video_quality, deleted_at)
		SELECT id, nickname, created_at, last_online, presence_visibility, photo_quality, video_quality, $2 FROM removed`
		result, err = tx.ExecContext(ctx, query, userID, deletedAt)
	case "restoring_owner":
		const query = `WITH restored AS (
			DELETE FROM deleted_users WHERE id = $1 AND deleted_at = $2
				AND deleted_at + INTERVAL '336 hours' > clock_timestamp()
			RETURNING id, nickname, created_at, last_online, presence_visibility, photo_quality, video_quality
		)
		INSERT INTO users (id, nickname, created_at, last_online, presence_visibility, photo_quality, video_quality)
		SELECT id, nickname, created_at, last_online, presence_visibility, photo_quality, video_quality FROM restored`
		result, err = tx.ExecContext(ctx, query, userID, deletedAt)
	case "restoring_moderator":
		const query = `WITH restored AS (
			DELETE FROM deleted_users WHERE id = $1 AND deleted_at = $2
				AND ((deleted_at AT TIME ZONE 'UTC') + INTERVAL '2 months') AT TIME ZONE 'UTC' > clock_timestamp()
			RETURNING id, nickname, created_at, last_online, presence_visibility, photo_quality, video_quality
		)
		INSERT INTO users (id, nickname, created_at, last_online, presence_visibility, photo_quality, video_quality)
		SELECT id, nickname, created_at, last_online, presence_visibility, photo_quality, video_quality FROM restored`
		result, err = tx.ExecContext(ctx, query, userID, deletedAt)
	case "purging":
		return r.purgeLifecycle(ctx, tx, userID, deletedAt)
	}

	if err != nil {
		return fmt.Errorf("apply account lifecycle: %w", err)
	}

	count, err = result.RowsAffected()

	if err != nil {
		return fmt.Errorf("apply account lifecycle: %w", err)
	}

	if count != 1 {
		return ErrLifecycleConflict
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit account lifecycle: %w", err)
	}

	return nil
}

// Serialize provisioning with archive and purge, including delayed requests.
func lockUserLifecycle(ctx context.Context, tx *sql.Tx, userID uuid.UUID) error {
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, userID.String()); err != nil {
		return fmt.Errorf("lock user lifecycle: %w", err)
	}

	return nil
}

func (r *userRepo) purgeLifecycle(ctx context.Context, tx *sql.Tx, userID uuid.UUID, deletedAt time.Time) error {
	const query = `DELETE FROM deleted_users WHERE id = $1 AND deleted_at = $2
		AND ((deleted_at AT TIME ZONE 'UTC') + INTERVAL '2 months') AT TIME ZONE 'UTC' <= clock_timestamp()`

	result, err := tx.ExecContext(ctx, query, userID, deletedAt)

	if err != nil {
		return fmt.Errorf("purge archived profile: %w", err)
	}

	count, err := result.RowsAffected()

	if err != nil {
		return fmt.Errorf("purge archived profile: %w", err)
	}

	if count == 0 {
		var exists bool
		const check = `SELECT EXISTS (SELECT 1 FROM users WHERE id = $1)
			OR EXISTS (SELECT 1 FROM deleted_users WHERE id = $1)`

		if err := tx.QueryRowContext(ctx, check, userID).Scan(&exists); err != nil {
			return fmt.Errorf("check archived profile: %w", err)
		}

		if exists {
			return ErrLifecycleConflict
		}
	}

	if _, err := tx.ExecContext(ctx, `INSERT INTO content_purge_events (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING`, userID); err != nil {
		return fmt.Errorf("queue content cleanup: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM user_profile_images WHERE owner_id=$1`, userID); err != nil {
		return fmt.Errorf("purge profile images: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_profile_image_history WHERE owner_id=$1`, userID); err != nil {
		return fmt.Errorf("purge profile image history: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `SELECT public.user_purge_profile_image_reports($1)`, userID); err != nil {
		return fmt.Errorf("purge profile image reports: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM media_permission_grants WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("purge media grants: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM registration_provisions WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("purge registration provision: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM account_lifecycle_operations WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("purge lifecycle operations: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit account purge: %w", err)
	}

	return nil
}
