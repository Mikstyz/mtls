package credentials

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type RegistrationProvision struct {
	UserID     uuid.UUID
	LeaseID    uuid.UUID
	Nickname   string
	Attempt    int
	ValidUntil time.Time
}

const MaxRegistrationProvisionAttempts = 100

func (s *Store) ClaimRegistrationProvision(ctx context.Context) (RegistrationProvision, error) {
	leaseID, err := uuid.NewRandom()

	if err != nil {
		return RegistrationProvision{}, fmt.Errorf("generate provision lease: %w", err)
	}

	const query = `WITH selected AS (
			SELECT r.user_id FROM registrations r
			JOIN credentials c ON c.user_id = r.user_id
			WHERE r.confirmed_at IS NOT NULL AND NOT c.enabled
				AND r.provision_attempts < $2
				AND r.provision_after <= CURRENT_TIMESTAMP
				AND (r.provision_lease_until IS NULL OR r.provision_lease_until <= CURRENT_TIMESTAMP)
			ORDER BY r.provision_after, r.user_id
			LIMIT 1 FOR UPDATE OF r SKIP LOCKED
		)
		UPDATE registrations r SET provision_lease_id = $1,
			provision_lease_until = CURRENT_TIMESTAMP + INTERVAL '2 minutes',
			provision_attempts = provision_attempts + 1
		FROM selected WHERE r.user_id = selected.user_id
		RETURNING r.user_id, r.nickname, r.provision_attempts, r.provision_lease_until`

	var job RegistrationProvision
	err = s.db.QueryRowContext(ctx, query, leaseID, MaxRegistrationProvisionAttempts).Scan(&job.UserID, &job.Nickname, &job.Attempt, &job.ValidUntil)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return RegistrationProvision{}, sql.ErrNoRows
		}

		return RegistrationProvision{}, fmt.Errorf("claim registration provision: %w", err)
	}

	job.LeaseID = leaseID
	return job, nil
}

// ActivateRegistration is called only after user confirms profile creation.
func (s *Store) ActivateRegistration(ctx context.Context, job RegistrationProvision) error {
	tx, err := s.db.BeginTx(ctx, nil)

	if err != nil {
		return fmt.Errorf("begin registration activation: %w", err)
	}

	defer tx.Rollback()

	const lock = `SELECT 1 FROM registrations WHERE user_id = $1 AND provision_lease_id = $2
		AND confirmed_at IS NOT NULL FOR UPDATE`

	var found int

	if err := tx.QueryRowContext(ctx, lock, job.UserID, job.LeaseID).Scan(&found); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("registration activation lease no longer valid")
		}

		return fmt.Errorf("lock registration: %w", err)
	}

	const activate = `UPDATE credentials SET enabled = true WHERE user_id = $1 AND NOT enabled`

	result, err := tx.ExecContext(ctx, activate, job.UserID)

	if err != nil {
		return fmt.Errorf("activate credentials: %w", err)
	}

	count, err := result.RowsAffected()

	if err != nil || count != 1 {
		return errors.New("registration activation lease no longer valid")
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM registrations WHERE user_id = $1 AND provision_lease_id = $2`, job.UserID, job.LeaseID); err != nil {
		return fmt.Errorf("complete registration: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit registration activation: %w", err)
	}

	return nil
}

func (s *Store) RetryRegistrationProvision(ctx context.Context, job RegistrationProvision) error {
	const query = `UPDATE registrations SET provision_lease_id = NULL, provision_lease_until = NULL,
		provision_after = CURRENT_TIMESTAMP + (LEAST(3600, 10 * power(2, LEAST(provision_attempts, 8)) * (0.8 + random() * 0.4)) * INTERVAL '1 second')
		WHERE user_id = $1 AND provision_lease_id = $2`

	if _, err := s.db.ExecContext(ctx, query, job.UserID, job.LeaseID); err != nil {
		return fmt.Errorf("retry registration provision: %w", err)
	}

	return nil
}
