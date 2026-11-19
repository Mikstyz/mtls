package credentials

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// VerifyPasswordRevision returns the verified revision for a sensitive action.
func (s *Store) VerifyPasswordRevision(ctx context.Context, userID uuid.UUID, password string) (int64, error) {
	if len(password) > 1024 {
		return 0, ErrInvalidCredentials
	}

	var version int
	var salt, hash []byte
	var enabled bool
	var revision int64
	err := s.db.QueryRowContext(ctx, `SELECT password_version, password_salt, password_hash, enabled, password_revision FROM credentials WHERE user_id = $1`, userID).Scan(&version, &salt, &hash, &enabled, &revision)

	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrInvalidCredentials
	}

	if err != nil {
		return 0, fmt.Errorf("get credentials: %w", err)
	}

	if (version != 1 && version != 2) || len(salt) != 16 || len(hash) != keyLength {
		return 0, errors.New("invalid stored password data")
	}

	actual, err := s.hashPasswordVersion(ctx, version, password, salt)

	if err != nil {
		return 0, fmt.Errorf("verify password: %w", err)
	}

	if subtle.ConstantTimeCompare(actual, hash) != 1 || !enabled {
		return 0, ErrInvalidCredentials
	}

	return revision, nil
}

func (s *Store) RequestEmailVerification(ctx context.Context, userID, sessionID uuid.UUID, passwordRevision int64, tokenHash [32]byte, key []byte) error {
	aead, err := registrationAEAD(key)

	if err != nil {
		return err
	}

	id, err := uuid.NewRandom()

	if err != nil {
		return fmt.Errorf("generate email verification id: %w", err)
	}

	var secret [32]byte

	if _, err := rand.Read(secret[:]); err != nil {
		return fmt.Errorf("generate email verification token: %w", err)
	}

	token := base64.RawURLEncoding.EncodeToString(secret[:])
	hash := sha256.Sum256([]byte(token))
	nonce := make([]byte, aead.NonceSize())

	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate email verification nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, []byte(token), id[:])
	tx, err := s.db.BeginTx(ctx, nil)

	if err != nil {
		return fmt.Errorf("begin email verification: %w", err)
	}

	defer tx.Rollback()

	var valid int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM credentials WHERE user_id = $1 AND enabled AND password_revision = $2 FOR SHARE`, userID, passwordRevision).Scan(&valid)

	if errors.Is(err, sql.ErrNoRows) {
		return ErrInvalidCredentials
	}

	if err != nil {
		return fmt.Errorf("check email verification credentials: %w", err)
	}

	err = tx.QueryRowContext(ctx, `SELECT 1 FROM sessions WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL
		AND expires_at > clock_timestamp() AND last_seen_at > clock_timestamp() - INTERVAL '168 hours' FOR SHARE`, sessionID, userID).Scan(&valid)

	if errors.Is(err, sql.ErrNoRows) {
		return ErrInvalidCredentials
	}

	if err != nil {
		return fmt.Errorf("check email verification session: %w", err)
	}

	if err := checkLockedSessionDeadline(ctx, tx, userID, sessionID, tokenHash); err != nil {
		return err
	}

	const query = `INSERT INTO password_resets (id, user_id, email, password_revision, token_hash, token_nonce, token_ciphertext, expires_at, purpose)
		SELECT $1, user_id, email, password_revision, $2, $3, $4, CURRENT_TIMESTAMP + INTERVAL '1 hour', 'verify_email'
		FROM credentials WHERE user_id = $5 AND enabled AND NOT email_verified`

	if _, err := tx.ExecContext(ctx, query, id, hash[:], nonce, ciphertext, userID); err != nil {
		return fmt.Errorf("queue email verification: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit email verification: %w", err)
	}

	return nil
}

func (s *Store) ConfirmEmailVerification(ctx context.Context, token string) error {
	if len(token) != 43 {
		return ErrInvalidConfirmation
	}

	decoded, err := base64.RawURLEncoding.DecodeString(token)

	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != token {
		return ErrInvalidConfirmation
	}

	hash := sha256.Sum256([]byte(token))
	tx, err := s.db.BeginTx(ctx, nil)

	if err != nil {
		return fmt.Errorf("begin email verification: %w", err)
	}

	defer tx.Rollback()

	var userID uuid.UUID
	err = tx.QueryRowContext(ctx, `SELECT user_id FROM password_resets WHERE token_hash = $1 AND purpose = 'verify_email' AND expires_at > CURRENT_TIMESTAMP`, hash[:]).Scan(&userID)

	if errors.Is(err, sql.ErrNoRows) {
		return ErrInvalidConfirmation
	}

	if err != nil {
		return fmt.Errorf("lookup email verification: %w", err)
	}

	var enabled bool
	var revision int64
	var email string
	err = tx.QueryRowContext(ctx, `SELECT enabled, password_revision, email FROM credentials WHERE user_id = $1 FOR UPDATE`, userID).Scan(&enabled, &revision, &email)

	if errors.Is(err, sql.ErrNoRows) || (err == nil && !enabled) {
		return ErrInvalidConfirmation
	}

	if err != nil {
		return fmt.Errorf("lock credentials for email verification: %w", err)
	}

	var found int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM password_resets WHERE user_id = $1 AND token_hash = $2 AND password_revision = $3 AND email = $4 AND purpose = 'verify_email' AND expires_at > clock_timestamp() FOR UPDATE`, userID, hash[:], revision, email).Scan(&found)

	if errors.Is(err, sql.ErrNoRows) {
		return ErrInvalidConfirmation
	}

	if err != nil {
		return fmt.Errorf("lock email verification: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `UPDATE credentials SET email_verified = true WHERE user_id = $1 AND enabled`, userID); err != nil {
		return fmt.Errorf("verify email: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM password_resets WHERE user_id = $1 AND purpose = 'verify_email'`, userID); err != nil {
		return fmt.Errorf("consume email verifications: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit email verification: %w", err)
	}

	return nil
}
