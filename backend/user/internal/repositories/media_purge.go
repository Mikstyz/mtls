package repositories

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
)

func (r *userRepo) NextMediaPurge(ctx context.Context) (uuid.UUID, error) {
	const query = `WITH due AS (
     SELECT user_id FROM content_purge_events
     WHERE NOT media_finished AND media_retry_at <= clock_timestamp()
     ORDER BY media_retry_at, user_id LIMIT 1 FOR UPDATE SKIP LOCKED
 )
 UPDATE content_purge_events e SET media_retry_at=clock_timestamp()+interval '3 seconds'
 FROM due WHERE e.user_id=due.user_id RETURNING e.user_id`

	var owner uuid.UUID
	err := r.db.QueryRowContext(ctx, query).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, nil
	}

	return owner, err
}

func (r *userRepo) FinishMediaPurge(ctx context.Context, owner uuid.UUID) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := lockUserLifecycle(ctx, tx, owner); err != nil {
		return err
	}

	var finished bool
	err = tx.QueryRowContext(ctx, `SELECT media_finished FROM content_purge_events WHERE user_id=$1 FOR UPDATE`, owner).Scan(&finished)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if finished {
		return nil
	}

	var pending bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM media_permissions WHERE owner_id=$1 AND revoked_at IS NULL)`, owner).Scan(&pending)
	if err != nil {
		return err
	}
	if pending {
		return ErrMediaConflict
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM media_permissions WHERE owner_id=$1`, owner); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `UPDATE content_purge_events SET media_finished=TRUE WHERE user_id=$1`, owner); err != nil {
		return err
	}
	return tx.Commit()
}
