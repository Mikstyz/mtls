package credentials

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

type PasswordResetMail struct {
	ID      uuid.UUID
	LeaseID uuid.UUID
	Email   string
	Token   string
}

func (s *Store) ClaimPasswordResetMail(ctx context.Context, key []byte, previousKeys ...[]byte) (PasswordResetMail, error) {
	return s.claimAccountMail(ctx, key, "password_reset", previousKeys)
}

func (s *Store) ClaimEmailVerificationMail(ctx context.Context, key []byte, previousKeys ...[]byte) (PasswordResetMail, error) {
	return s.claimAccountMail(ctx, key, "verify_email", previousKeys)
}

func (s *Store) ClaimEmailChangeMail(ctx context.Context, key []byte, previousKeys ...[]byte) (PasswordResetMail, error) {
	return s.claimAccountMail(ctx, key, "change_email", previousKeys)
}

func (s *Store) claimAccountMail(ctx context.Context, key []byte, purpose string, previousKeys [][]byte) (PasswordResetMail, error) {
	if _, err := registrationAEAD(key); err != nil {
		return PasswordResetMail{}, err
	}

	leaseID, err := uuid.NewRandom()

	if err != nil {
		return PasswordResetMail{}, fmt.Errorf("generate password reset lease: %w", err)
	}

	const query = `WITH selected AS (
			SELECT p.id FROM password_resets p JOIN credentials c ON c.user_id = p.user_id
			WHERE p.token_ciphertext IS NOT NULL AND p.expires_at > CURRENT_TIMESTAMP AND p.purpose = $2
				AND p.available_at <= CURRENT_TIMESTAMP AND c.enabled
				AND p.email = c.email AND p.password_revision = c.password_revision
				AND (p.lease_until IS NULL OR p.lease_until <= CURRENT_TIMESTAMP)
			ORDER BY p.available_at, p.id LIMIT 1 FOR UPDATE OF p SKIP LOCKED
		), claimed AS (
			UPDATE password_resets p SET lease_id = $1,
				lease_until = CURRENT_TIMESTAMP + INTERVAL '2 minutes', attempts = attempts + 1
			FROM selected WHERE p.id = selected.id
			RETURNING p.id, COALESCE(p.pending_email,p.email) AS recipient, p.token_nonce, p.token_ciphertext
		)
		SELECT id, recipient, token_nonce, token_ciphertext FROM claimed`

	var job PasswordResetMail
	var nonce, ciphertext []byte
	err = s.db.QueryRowContext(ctx, query, leaseID, purpose).Scan(&job.ID, &job.Email, &nonce, &ciphertext)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return PasswordResetMail{}, sql.ErrNoRows
		}

		return PasswordResetMail{}, fmt.Errorf("claim password reset email: %w", err)
	}

	plaintext, err := openDeliveryToken(key, previousKeys, nonce, ciphertext, job.ID[:])

	if err != nil {
		return PasswordResetMail{}, errors.New("cannot decrypt password reset email")
	}

	job.LeaseID = leaseID
	job.Token = string(plaintext)

	return job, nil
}

func (s *Store) CompletePasswordResetMail(ctx context.Context, job PasswordResetMail) error {
	const query = `UPDATE password_resets SET token_nonce = NULL, token_ciphertext = NULL,
		lease_id = NULL, lease_until = NULL WHERE id = $1 AND lease_id = $2`

	if _, err := s.db.ExecContext(ctx, query, job.ID, job.LeaseID); err != nil {
		return fmt.Errorf("complete password reset email: %w", err)
	}

	return nil
}

func (s *Store) RetryPasswordResetMail(ctx context.Context, job PasswordResetMail) error {
	const query = `UPDATE password_resets SET lease_id = NULL, lease_until = NULL,
		available_at = CURRENT_TIMESTAMP + (LEAST(3600, 10 * power(2, LEAST(attempts, 8)) * (0.8 + random() * 0.4)) * INTERVAL '1 second')
		WHERE id = $1 AND lease_id = $2`

	if _, err := s.db.ExecContext(ctx, query, job.ID, job.LeaseID); err != nil {
		return fmt.Errorf("retry password reset email: %w", err)
	}

	return nil
}

func (s *Store) CleanupPasswordResets(ctx context.Context) error {
	const query = `DELETE FROM password_resets WHERE id IN (
		SELECT id FROM password_resets WHERE expires_at <= CURRENT_TIMESTAMP
		ORDER BY expires_at, id LIMIT 100 FOR UPDATE SKIP LOCKED)`

	if _, err := s.db.ExecContext(ctx, query); err != nil {
		return fmt.Errorf("cleanup password resets: %w", err)
	}

	return nil
}
