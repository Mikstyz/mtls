package credentials

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

var ErrAccountLifecycle = errors.New("account operation unavailable")

type AccountLifecycle struct {
	UserID      uuid.UUID
	OperationID uuid.UUID
	LeaseID     uuid.UUID
	State       string
	DeletedAt   time.Time
}

// BeginAccountDeletion disables the account and revokes every session atomically.
func (s *Store) BeginAccountDeletion(ctx context.Context, userID, sessionID uuid.UUID, revision int64, tokenHash [32]byte) error {
	opID, err := uuid.NewRandom()

	if err != nil {
		return fmt.Errorf("generate deletion operation: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)

	if err != nil {
		return fmt.Errorf("begin account deletion: %w", err)
	}

	defer tx.Rollback()

	// Lock credentials before the session; changing enabled revokes sessions via a trigger.
	var credentialFound int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM credentials
		WHERE user_id = $1 AND enabled AND password_revision = $2 FOR UPDATE`, userID, revision).Scan(&credentialFound)

	if errors.Is(err, sql.ErrNoRows) {
		return ErrAccountLifecycle
	}

	if err != nil {
		return fmt.Errorf("lock deletion credentials: %w", err)
	}

	var valid int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM sessions WHERE user_id = $1 AND id = $2 AND revoked_at IS NULL AND expires_at > CURRENT_TIMESTAMP AND last_seen_at > CURRENT_TIMESTAMP - INTERVAL '168 hours' FOR UPDATE`, userID, sessionID).Scan(&valid)

	if errors.Is(err, sql.ErrNoRows) {
		return ErrAccountLifecycle
	}

	if err != nil {
		return fmt.Errorf("lock deletion session: %w", err)
	}

	if err := checkLockedSessionDeadline(ctx, tx, userID, sessionID, tokenHash); err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			return ErrAccountLifecycle
		}

		return err
	}

	if _, err := tx.ExecContext(ctx, `UPDATE credentials SET enabled = false, password_revision = password_revision + 1 WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("disable account: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = $1 AND revoked_at IS NULL`, userID); err != nil {
		return fmt.Errorf("revoke sessions for deletion: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM password_resets WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("revoke account tokens: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM account_roles WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("revoke account roles: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `INSERT INTO account_deletions (user_id, state, operation_id) VALUES ($1, 'deleting', $2)`, userID, opID); err != nil {
		return fmt.Errorf("queue account deletion: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit account deletion: %w", err)
	}

	return nil
}

// VerifyDeleted checks the password for an archived account; callers must rate-limit it.
func (s *Store) VerifyDeleted(ctx context.Context, identifier, password string) (uuid.UUID, int64, error) {
	identifier = strings.ToLower(strings.TrimSpace(identifier))

	if len(identifier) == 0 || len(identifier) > 254 || len(password) > 1024 {
		return uuid.Nil, 0, ErrInvalidCredentials
	}

	const query = `SELECT c.user_id, c.password_version, c.password_revision, c.password_salt, c.password_hash
		FROM credentials c JOIN account_deletions d ON d.user_id = c.user_id
		WHERE (c.login = $1 OR c.email = $1) AND NOT c.enabled AND d.state = 'deleted'`

	var id uuid.UUID
	var version int
	var revision int64
	var salt, hash []byte
	err := s.db.QueryRowContext(ctx, query, identifier).Scan(&id, &version, &revision, &salt, &hash)

	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, 0, fmt.Errorf("get deleted credentials: %w", err)
	}

	found := err == nil

	if !found {
		salt = make([]byte, 16)
		hash = make([]byte, keyLength)
		version = 1
	} else if (version != 1 && version != 2) || len(salt) != 16 || len(hash) != keyLength {
		return uuid.Nil, 0, errors.New("invalid stored password data")
	}

	actual, err := s.hashPasswordVersion(ctx, version, password, salt)

	if err != nil {
		return uuid.Nil, 0, fmt.Errorf("verify deleted credentials: %w", err)
	}

	if subtle.ConstantTimeCompare(actual, hash) != 1 || !found {
		return uuid.Nil, 0, ErrInvalidCredentials
	}

	return id, revision, nil
}

// BeginOwnerRestore must only be used after verifying the deleted account's password.
func (s *Store) BeginOwnerRestore(ctx context.Context, userID uuid.UUID, revision int64) error {
	opID, err := uuid.NewRandom()

	if err != nil {
		return fmt.Errorf("generate restore operation: %w", err)
	}

	const query = `UPDATE account_deletions d SET state = $1, operation_id = $2,
		available_at = CURRENT_TIMESTAMP, attempts = 0
		FROM credentials c WHERE d.user_id = $3 AND c.user_id = d.user_id
			AND NOT c.enabled AND c.password_revision = $4 AND d.state = 'deleted'
			AND d.deleted_at + INTERVAL '336 hours' > clock_timestamp()`

	result, err := s.db.ExecContext(ctx, query, "restoring_owner", opID, userID, revision)

	if err != nil {
		return fmt.Errorf("queue account restore: %w", err)
	}

	count, err := result.RowsAffected()

	if err != nil || count != 1 {
		return ErrAccountLifecycle
	}

	return nil
}

// BeginModeratorRestore rechecks the moderator's role, session and password revision in one transaction.
func (s *Store) BeginModeratorRestore(ctx context.Context, moderatorID, sessionID, targetID uuid.UUID, revision int64, tokenHash [32]byte) error {
	opID, err := uuid.NewRandom()

	if err != nil {
		return fmt.Errorf("generate moderator restore operation: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)

	if err != nil {
		return fmt.Errorf("begin moderator restore: %w", err)
	}

	defer tx.Rollback()

	const authorize = `SELECT 1 FROM credentials c
		JOIN account_roles r ON r.user_id = c.user_id AND r.role = 'moderator'
		JOIN sessions s ON s.user_id = c.user_id
		WHERE c.user_id = $1 AND c.enabled AND c.password_revision = $2
			AND s.id = $3 AND s.revoked_at IS NULL AND s.expires_at > CURRENT_TIMESTAMP
			AND s.last_seen_at > CURRENT_TIMESTAMP - INTERVAL '168 hours'
		FOR SHARE OF c, r, s`

	var authorized int
	err = tx.QueryRowContext(ctx, authorize, moderatorID, revision, sessionID).Scan(&authorized)

	if errors.Is(err, sql.ErrNoRows) {
		return ErrAccountLifecycle
	}

	if err != nil {
		return fmt.Errorf("authorize moderator restore: %w", err)
	}

	if err := checkLockedSessionDeadline(ctx, tx, moderatorID, sessionID, tokenHash); err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			return ErrAccountLifecycle
		}

		return err
	}

	const update = `UPDATE account_deletions d SET state = 'restoring_moderator', operation_id = $1,
		available_at = CURRENT_TIMESTAMP, attempts = 0
		FROM credentials c WHERE d.user_id = $2 AND c.user_id = d.user_id
			AND NOT c.enabled AND d.state = 'deleted'
			AND ((d.deleted_at AT TIME ZONE 'UTC') + INTERVAL '2 months') AT TIME ZONE 'UTC' > clock_timestamp()`

	result, err := tx.ExecContext(ctx, update, opID, targetID)

	if err != nil {
		return fmt.Errorf("queue moderator restore: %w", err)
	}

	count, err := result.RowsAffected()

	if err != nil || count != 1 {
		return ErrAccountLifecycle
	}

	const audit = `INSERT INTO account_moderation_events (operation_id, actor_id, target_id, action, outcome)
		VALUES ($1, $2, $3, 'restore', 'requested')`

	if _, err := tx.ExecContext(ctx, audit, opID, moderatorID, targetID); err != nil {
		return fmt.Errorf("record moderator restore: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit moderator restore: %w", err)
	}

	return nil
}

func (s *Store) ClaimAccountLifecycle(ctx context.Context) (AccountLifecycle, error) {
	leaseID, err := uuid.NewRandom()

	if err != nil {
		return AccountLifecycle{}, fmt.Errorf("generate account lifecycle lease: %w", err)
	}

	purgeID, err := uuid.NewRandom()

	if err != nil {
		return AccountLifecycle{}, fmt.Errorf("generate account purge operation: %w", err)
	}

	const query = `WITH selected AS (
		SELECT user_id FROM account_deletions
		WHERE available_at <= CURRENT_TIMESTAMP AND (lease_until IS NULL OR lease_until <= CURRENT_TIMESTAMP)
			AND (state <> 'deleted' OR ((deleted_at AT TIME ZONE 'UTC') + INTERVAL '2 months') AT TIME ZONE 'UTC' <= CURRENT_TIMESTAMP)
		ORDER BY available_at, user_id LIMIT 1 FOR UPDATE SKIP LOCKED
	)
	UPDATE account_deletions d SET
		operation_id = CASE WHEN d.state = 'deleted' THEN $2 ELSE d.operation_id END,
		state = CASE WHEN d.state = 'deleted' THEN 'purging' ELSE d.state END,
		lease_id = $1, lease_until = CURRENT_TIMESTAMP + INTERVAL '2 minutes', attempts = attempts + 1
	FROM selected WHERE d.user_id = selected.user_id
	RETURNING d.user_id, d.operation_id, d.state, d.deleted_at`

	var job AccountLifecycle
	err = s.db.QueryRowContext(ctx, query, leaseID, purgeID).Scan(&job.UserID, &job.OperationID, &job.State, &job.DeletedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AccountLifecycle{}, sql.ErrNoRows
		}

		return AccountLifecycle{}, fmt.Errorf("claim account lifecycle: %w", err)
	}

	job.LeaseID = leaseID
	return job, nil
}

func (s *Store) CompleteAccountLifecycle(ctx context.Context, job AccountLifecycle) error {
	tx, err := s.db.BeginTx(ctx, nil)

	if err != nil {
		return fmt.Errorf("begin account lifecycle completion: %w", err)
	}

	defer tx.Rollback()

	var state string
	err = tx.QueryRowContext(ctx, `SELECT state FROM account_deletions WHERE user_id = $1 AND operation_id = $2 AND lease_id = $3 FOR UPDATE`, job.UserID, job.OperationID, job.LeaseID).Scan(&state)

	if errors.Is(err, sql.ErrNoRows) {
		return ErrAccountLifecycle
	}

	if err != nil {
		return fmt.Errorf("lock account lifecycle: %w", err)
	}

	if state != job.State {
		return ErrAccountLifecycle
	}

	switch state {
	case "deleting":
		_, err = tx.ExecContext(ctx, `UPDATE account_deletions SET state = 'deleted', lease_id = NULL, lease_until = NULL WHERE user_id = $1`, job.UserID)
	case "restoring_owner", "restoring_moderator":
		var result sql.Result
		result, err = tx.ExecContext(ctx, `UPDATE credentials SET enabled = true, password_revision = password_revision + 1 WHERE user_id = $1 AND NOT enabled`, job.UserID)

		if err == nil {
			count, countErr := result.RowsAffected()

			if countErr != nil || count != 1 {
				return ErrAccountLifecycle
			}

			if state == "restoring_moderator" {
				_, err = tx.ExecContext(ctx, `UPDATE account_moderation_events SET outcome = 'completed', updated_at = CURRENT_TIMESTAMP WHERE operation_id = $1`, job.OperationID)
			}

			if err != nil {
				return fmt.Errorf("complete moderator audit: %w", err)
			}

			_, err = tx.ExecContext(ctx, `DELETE FROM account_deletions WHERE user_id = $1`, job.UserID)
		}
	case "purging":
		var enabled bool
		err = tx.QueryRowContext(ctx, `SELECT enabled FROM credentials WHERE user_id = $1 FOR UPDATE`, job.UserID).Scan(&enabled)

		if err == nil && enabled {
			return ErrAccountLifecycle
		}

		if err == nil {
			_, err = tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = $1`, job.UserID)
		}

		if err == nil {
			var result sql.Result
			result, err = tx.ExecContext(ctx, `DELETE FROM credentials WHERE user_id = $1 AND NOT enabled`, job.UserID)

			if err == nil {
				count, countErr := result.RowsAffected()

				if countErr != nil || count != 1 {
					return ErrAccountLifecycle
				}
			}
		}
	default:
		return ErrAccountLifecycle
	}

	if err != nil {
		return fmt.Errorf("complete account lifecycle: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit account lifecycle: %w", err)
	}

	return nil
}

func (s *Store) RetryAccountLifecycle(ctx context.Context, job AccountLifecycle) error {
	const query = `UPDATE account_deletions SET lease_id = NULL, lease_until = NULL,
		available_at = CURRENT_TIMESTAMP + (LEAST(3600, 10 * power(2, LEAST(attempts, 8)) * (0.8 + random() * 0.4)) * INTERVAL '1 second')
		WHERE user_id = $1 AND operation_id = $2 AND lease_id = $3`

	if _, err := s.db.ExecContext(ctx, query, job.UserID, job.OperationID, job.LeaseID); err != nil {
		return fmt.Errorf("retry account lifecycle: %w", err)
	}

	return nil
}

// RejectAccountRestore returns an unapplied restore to the archived state.
func (s *Store) RejectAccountRestore(ctx context.Context, job AccountLifecycle) error {
	if job.State != "restoring_owner" && job.State != "restoring_moderator" {
		return ErrAccountLifecycle
	}

	const query = `WITH rejected AS (
		UPDATE account_deletions SET state = 'deleted', lease_id = NULL,
			lease_until = NULL, available_at = CURRENT_TIMESTAMP, attempts = 0
		WHERE user_id = $1 AND operation_id = $2 AND lease_id = $3 AND state = $4
		RETURNING operation_id
	)
	UPDATE account_moderation_events SET outcome = 'rejected', updated_at = CURRENT_TIMESTAMP
	WHERE operation_id IN (SELECT operation_id FROM rejected)`

	if _, err := s.db.ExecContext(ctx, query, job.UserID, job.OperationID, job.LeaseID, job.State); err != nil {
		return fmt.Errorf("reject account restore: %w", err)
	}

	return nil
}
