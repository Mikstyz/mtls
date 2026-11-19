package credentials

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

type RegistrationMail struct {
	UserID  uuid.UUID
	LeaseID uuid.UUID
	Email   string
	Token   string
}

// ClaimRegistrationMail leases one unconfirmed, unexpired delivery job.
func (s *Store) ClaimRegistrationMail(ctx context.Context, deliveryKey []byte, previousKeys ...[]byte) (RegistrationMail, error) {
	if _, err := registrationAEAD(deliveryKey); err != nil {
		return RegistrationMail{}, err
	}

	leaseID, err := uuid.NewRandom()

	if err != nil {
		return RegistrationMail{}, fmt.Errorf("generate delivery lease: %w", err)
	}

	const query = `WITH selected AS (
			SELECT j.user_id FROM registration_mail_jobs j
			JOIN registrations r ON r.user_id = j.user_id
			WHERE j.available_at <= CURRENT_TIMESTAMP
				AND (j.lease_until IS NULL OR j.lease_until <= CURRENT_TIMESTAMP)
				AND r.confirmed_at IS NULL AND r.expires_at > CURRENT_TIMESTAMP
			ORDER BY j.available_at, j.user_id
			LIMIT 1 FOR UPDATE OF j SKIP LOCKED
		), claimed AS (
			UPDATE registration_mail_jobs j SET lease_id = $1,
				lease_until = CURRENT_TIMESTAMP + INTERVAL '2 minutes', attempts = attempts + 1
			FROM selected WHERE j.user_id = selected.user_id
			RETURNING j.user_id, j.token_nonce, j.token_ciphertext
		)
		SELECT claimed.user_id, credentials.email, claimed.token_nonce, claimed.token_ciphertext
		FROM claimed JOIN credentials ON credentials.user_id = claimed.user_id`

	var job RegistrationMail
	var nonce, ciphertext []byte
	err = s.db.QueryRowContext(ctx, query, leaseID).Scan(&job.UserID, &job.Email, &nonce, &ciphertext)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return RegistrationMail{}, sql.ErrNoRows
		}

		return RegistrationMail{}, fmt.Errorf("claim registration email: %w", err)
	}

	plaintext, err := openDeliveryToken(deliveryKey, previousKeys, nonce, ciphertext, job.UserID[:])

	if err != nil {
		return RegistrationMail{}, errors.New("cannot decrypt registration email")
	}

	job.LeaseID = leaseID
	job.Token = string(plaintext)

	return job, nil
}

// CompleteRegistrationMail removes ciphertext only when the caller owns the lease.
func (s *Store) CompleteRegistrationMail(ctx context.Context, job RegistrationMail) error {
	const query = `DELETE FROM registration_mail_jobs WHERE user_id = $1 AND lease_id = $2`

	if _, err := s.db.ExecContext(ctx, query, job.UserID, job.LeaseID); err != nil {
		return fmt.Errorf("complete registration email: %w", err)
	}

	return nil
}

// RetryRegistrationMail releases a lease with bounded exponential backoff.
func (s *Store) RetryRegistrationMail(ctx context.Context, job RegistrationMail) error {
	const query = `UPDATE registration_mail_jobs SET lease_id = NULL, lease_until = NULL,
		available_at = CURRENT_TIMESTAMP + (LEAST(3600, 10 * power(2, LEAST(attempts, 8)) * (0.8 + random() * 0.4)) * INTERVAL '1 second')
		WHERE user_id = $1 AND lease_id = $2`

	if _, err := s.db.ExecContext(ctx, query, job.UserID, job.LeaseID); err != nil {
		return fmt.Errorf("retry registration email: %w", err)
	}

	return nil
}
