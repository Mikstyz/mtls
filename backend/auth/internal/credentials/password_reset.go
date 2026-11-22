package credentials

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

var ErrInvalidReset = errors.New("invalid or expired password reset")

// CheckRecoveryLoginProof checks an email token without consuming it; session creation
// must recheck and consume the same token atomically with the new session.
func (s *Store) CheckRecoveryLoginProof(ctx context.Context, identifier, token string) ([32]byte, bool, error) {
	var hash [32]byte
	identifier = strings.ToLower(strings.TrimSpace(identifier))

	if len(identifier) == 0 || len(identifier) > 254 || len(token) != 43 {
		return hash, false, nil
	}

	decoded, err := base64.RawURLEncoding.DecodeString(token)

	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != token {
		return hash, false, nil
	}

	hash = sha256.Sum256([]byte(token))
	const query = `SELECT EXISTS (SELECT 1 FROM password_resets p
		JOIN credentials c ON c.user_id = p.user_id
		WHERE (c.login = $1 OR c.email = $1) AND c.enabled AND c.email_verified
			AND p.token_hash = $2 AND p.purpose = 'password_reset'
			AND p.password_revision = c.password_revision AND p.email = c.email
			AND p.expires_at > clock_timestamp())`

	var valid bool

	if err := s.db.QueryRowContext(ctx, query, identifier, hash[:]).Scan(&valid); err != nil {
		return hash, false, fmt.Errorf("check recovery login proof: %w", err)
	}

	return hash, valid, nil
}

// RequestPasswordReset has the same result for known and unknown addresses.
func (s *Store) RequestPasswordReset(ctx context.Context, email string, deliveryKey []byte) error {
	email = strings.ToLower(strings.TrimSpace(email))

	if len(email) == 0 || len(email) > 254 {
		return ErrInvalidAccountDetails
	}

	aead, err := registrationAEAD(deliveryKey)

	if err != nil {
		return err
	}

	id, err := uuid.NewRandom()

	if err != nil {
		return fmt.Errorf("generate password reset id: %w", err)
	}

	var secret [32]byte

	if _, err := rand.Read(secret[:]); err != nil {
		return fmt.Errorf("generate password reset token: %w", err)
	}

	token := base64.RawURLEncoding.EncodeToString(secret[:])
	tokenHash := sha256.Sum256([]byte(token))
	nonce := make([]byte, aead.NonceSize())

	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate password reset nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, []byte(token), id[:])
	const query = `INSERT INTO password_resets (id, user_id, email, password_revision, token_hash, token_nonce, token_ciphertext, expires_at)
		SELECT $1, user_id, email, password_revision, $2, $3, $4, CURRENT_TIMESTAMP + INTERVAL '1 hour'
		FROM credentials WHERE email = $5 AND enabled AND email_verified`

	if _, err := s.db.ExecContext(ctx, query, id, tokenHash[:], nonce, ciphertext, email); err != nil {
		return fmt.Errorf("queue password reset: %w", err)
	}

	return nil
}

// ResetPassword consumes a token, replaces the password and revokes all sessions atomically.
func (s *Store) ResetPassword(ctx context.Context, token, password string) error {
	if !s.allowedPassword(password) {
		return ErrInvalidPassword
	}

	if len(token) != 43 {
		return ErrInvalidReset
	}

	decoded, err := base64.RawURLEncoding.DecodeString(token)

	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != token {
		return ErrInvalidReset
	}

	hash := sha256.Sum256([]byte(token))
	var userID uuid.UUID
	err = s.db.QueryRowContext(ctx, `SELECT p.user_id
		FROM password_resets p JOIN credentials c USING(user_id)
		WHERE p.token_hash=$1 AND p.purpose='password_reset' AND p.expires_at>statement_timestamp()
			AND c.enabled AND c.email_verified AND c.email=p.email
			AND c.password_revision=p.password_revision`, hash[:]).Scan(&userID)

	if errors.Is(err, sql.ErrNoRows) {
		return ErrInvalidReset
	}

	if err != nil {
		return fmt.Errorf("lookup password reset: %w", err)
	}

	var salt [16]byte

	if _, err := rand.Read(salt[:]); err != nil {
		return fmt.Errorf("generate password salt: %w", err)
	}

	passwordHash, err := s.hashPasswordVersion(ctx, s.newPasswordVersion(), password, salt[:])

	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)

	if err != nil {
		return fmt.Errorf("begin password reset: %w", err)
	}

	defer tx.Rollback()

	var enabled bool
	var revision int64
	var email string
	err = tx.QueryRowContext(ctx, `SELECT enabled AND email_verified, password_revision, email FROM credentials WHERE user_id = $1 FOR UPDATE`, userID).Scan(&enabled, &revision, &email)

	if errors.Is(err, sql.ErrNoRows) || (err == nil && !enabled) {
		return ErrInvalidReset
	}

	if err != nil {
		return fmt.Errorf("lock credentials for reset: %w", err)
	}

	valid, err := lockUnexpiredEmailToken(ctx, tx, userID, hash, revision, email, "password_reset")
	if err != nil {
		return fmt.Errorf("check password reset token: %w", err)
	}
	if !valid {
		return ErrInvalidReset
	}

	const update = `UPDATE credentials SET password_salt = $1, password_hash = $2,
		password_version = $4, password_revision = password_revision + 1 WHERE user_id = $3 AND enabled`

	if _, err := tx.ExecContext(ctx, update, salt[:], passwordHash, userID, s.newPasswordVersion()); err != nil {
		return fmt.Errorf("update reset password: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = $1 AND revoked_at IS NULL`, userID); err != nil {
		return fmt.Errorf("revoke sessions after password reset: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM password_resets WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("consume password resets: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit password reset: %w", err)
	}

	return nil
}
