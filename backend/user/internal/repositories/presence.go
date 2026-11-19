package repositories

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// RecordPresence must only be called for a session authenticated by auth.
func (r *userRepo) RecordPresence(ctx context.Context, userID, sessionID uuid.UUID) error {
	const query = `
		WITH active_user AS (
			UPDATE users SET last_online = CURRENT_TIMESTAMP
			WHERE id = $1
			RETURNING id
		)
		INSERT INTO user_presence (user_id, session_id, last_seen)
		SELECT id, $2, CURRENT_TIMESTAMP FROM active_user
		ON CONFLICT (user_id, session_id)
		DO UPDATE SET last_seen = EXCLUDED.last_seen
	`

	result, err := r.db.ExecContext(ctx, query, userID, sessionID)

	if err != nil {
		return fmt.Errorf("record presence: %w", err)
	}

	if err := requireAffectedUser(result); err != nil {
		return fmt.Errorf("record presence: %w", err)
	}

	return nil
}

// RemovePresence is called when an authenticated session ends.
func (r *userRepo) RemovePresence(ctx context.Context, userID, sessionID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM user_presence WHERE user_id = $1 AND session_id = $2", userID, sessionID)

	if err != nil {
		return fmt.Errorf("remove presence: %w", err)
	}

	return nil
}

// PurgeStalePresence removes old heartbeat records without changing last_online.
func (r *userRepo) PurgeStalePresence(ctx context.Context) (int64, error) {
	const query = `
		DELETE FROM user_presence
		WHERE (user_id, session_id) IN (
			SELECT user_id, session_id FROM user_presence
			WHERE last_seen <= CURRENT_TIMESTAMP - INTERVAL '1 day'
			ORDER BY last_seen
			LIMIT 500
			FOR UPDATE SKIP LOCKED
		)
	`

	result, err := r.db.ExecContext(ctx, query)

	if err != nil {
		return 0, fmt.Errorf("purge stale presence: %w", err)
	}

	count, err := result.RowsAffected()

	if err != nil {
		return 0, fmt.Errorf("purge stale presence: %w", err)
	}

	return count, nil
}
