package recovery

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// InvalidateRestoredSessions advances the generation past every restored
// session without emitting events. Stop all service instances and writers first.
func InvalidateRestoredSessions(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)

	if err != nil {
		return fmt.Errorf("begin session recovery: %w", err)
	}

	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `LOCK TABLE sessions IN SHARE MODE`); err != nil {
		return fmt.Errorf("lock restored sessions: %w", err)
	}

	result, err := tx.ExecContext(ctx, `UPDATE session_epoch SET generation =
		GREATEST(generation, (SELECT COALESCE(MAX(recovery_generation), 0) FROM sessions)) + 1
		WHERE id`)

	if err != nil {
		return fmt.Errorf("invalidate restored sessions: %w", err)
	}

	count, err := result.RowsAffected()

	if err != nil {
		return fmt.Errorf("check session recovery generation: %w", err)
	}

	if count != 1 {
		return errors.New("session recovery generation is missing")
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit session recovery: %w", err)
	}

	return nil
}
