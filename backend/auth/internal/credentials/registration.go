package credentials

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

var ErrInvalidConfirmation = errors.New("invalid or expired confirmation")

// BeginRegistration reserves the credentials and stores only a hash of the token.
// The account remains disabled until a separately coordinated activation.
func (s *Store) BeginRegistration(ctx context.Context, id uuid.UUID, login, email, nickname string, deliveryKey []byte) error {
	var placeholder [32]byte

	if _, err := rand.Read(placeholder[:]); err != nil {
		return fmt.Errorf("generate placeholder password: %w", err)
	}

	password := base64.RawURLEncoding.EncodeToString(placeholder[:])
	login, email, err := validateAccount(id, login, email, password)

	if err != nil {
		return err
	}

	nickname = strings.TrimSpace(nickname)

	if !utf8.ValidString(nickname) || utf8.RuneCountInString(nickname) == 0 || utf8.RuneCountInString(nickname) > 64 || strings.IndexFunc(nickname, unicode.IsControl) >= 0 {
		return ErrInvalidAccountDetails
	}

	aead, err := registrationAEAD(deliveryKey)

	if err != nil {
		return err
	}

	var salt [16]byte
	var secret [32]byte

	if _, err := rand.Read(salt[:]); err != nil {
		return fmt.Errorf("generate password salt: %w", err)
	}

	if _, err := rand.Read(secret[:]); err != nil {
		return fmt.Errorf("generate confirmation token: %w", err)
	}

	passwordHash, err := s.hashPasswordVersion(ctx, s.newPasswordVersion(), password, salt[:])

	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	token := base64.RawURLEncoding.EncodeToString(secret[:])
	tokenHash := sha256.Sum256([]byte(token))
	nonce := make([]byte, aead.NonceSize())

	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate delivery nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, []byte(token), id[:])
	tx, err := s.db.BeginTx(ctx, nil)

	if err != nil {
		return fmt.Errorf("begin registration: %w", err)
	}

	defer tx.Rollback()

	const createCredentials = `INSERT INTO credentials (user_id, login, email, password_salt, password_hash, enabled, password_version)
		VALUES ($1, $2, $3, $4, $5, false, $6)`

	if _, err := tx.ExecContext(ctx, createCredentials, id, login, email, salt[:], passwordHash, s.newPasswordVersion()); err != nil {
		return fmt.Errorf("reserve credentials: %w", err)
	}

	const createRegistration = `INSERT INTO registrations (user_id, nickname, token_hash, expires_at)
		VALUES ($1, $2, $3, CURRENT_TIMESTAMP + INTERVAL '24 hours')`

	if _, err := tx.ExecContext(ctx, createRegistration, id, nickname, tokenHash[:]); err != nil {
		return fmt.Errorf("create registration: %w", err)
	}

	const createMailJob = `INSERT INTO registration_mail_jobs (user_id, token_nonce, token_ciphertext)
		VALUES ($1, $2, $3)`

	if _, err := tx.ExecContext(ctx, createMailJob, id, nonce, ciphertext); err != nil {
		return fmt.Errorf("queue confirmation email: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit registration: %w", err)
	}

	return nil
}

func registrationAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("registration delivery key must be 32 bytes")
	}

	block, err := aes.NewCipher(key)

	if err != nil {
		return nil, fmt.Errorf("initialize registration delivery key: %w", err)
	}

	return cipher.NewGCM(block)
}

func openDeliveryToken(key []byte, previousKeys [][]byte, nonce, ciphertext, associated []byte) ([]byte, error) {
	keys := make([][]byte, 0, len(previousKeys)+1)
	keys = append(keys, key)
	keys = append(keys, previousKeys...)

	for _, candidate := range keys {
		aead, err := registrationAEAD(candidate)

		if err != nil {
			return nil, err
		}

		if len(nonce) != aead.NonceSize() {
			return nil, errors.New("invalid delivery nonce")
		}

		plaintext, err := aead.Open(nil, nonce, ciphertext, associated)

		if err == nil {
			return plaintext, nil
		}
	}

	return nil, errors.New("cannot decrypt queued delivery")
}

// ResendRegistration replaces an unconfirmed token without extending its expiry.
// The same result is returned for unknown or ineligible addresses.
func (s *Store) ResendRegistration(ctx context.Context, email string, deliveryKey []byte) error {
	email = strings.ToLower(strings.TrimSpace(email))

	if len(email) == 0 || len(email) > 254 {
		return ErrInvalidAccountDetails
	}

	aead, err := registrationAEAD(deliveryKey)

	if err != nil {
		return err
	}

	var secret [32]byte

	if _, err := rand.Read(secret[:]); err != nil {
		return fmt.Errorf("generate confirmation token: %w", err)
	}

	token := base64.RawURLEncoding.EncodeToString(secret[:])
	hash := sha256.Sum256([]byte(token))
	nonce := make([]byte, aead.NonceSize())

	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate delivery nonce: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)

	if err != nil {
		return fmt.Errorf("begin registration resend: %w", err)
	}

	defer tx.Rollback()

	const lookup = `SELECT r.user_id FROM registrations r JOIN credentials c ON c.user_id = r.user_id
		WHERE c.email = $1 AND NOT c.enabled AND r.confirmed_at IS NULL
			AND r.expires_at > clock_timestamp() FOR UPDATE OF r`

	var id uuid.UUID
	err = tx.QueryRowContext(ctx, lookup, email).Scan(&id)

	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("lookup registration resend: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, []byte(token), id[:])

	if _, err := tx.ExecContext(ctx, `UPDATE registrations SET token_hash = $1 WHERE user_id = $2`, hash[:], id); err != nil {
		return fmt.Errorf("replace confirmation token: %w", err)
	}

	const queue = `INSERT INTO registration_mail_jobs (user_id, token_nonce, token_ciphertext)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id) DO UPDATE SET token_nonce = EXCLUDED.token_nonce,
			token_ciphertext = EXCLUDED.token_ciphertext, available_at = CURRENT_TIMESTAMP,
			lease_id = NULL, lease_until = NULL, attempts = 0`

	if _, err := tx.ExecContext(ctx, queue, id, nonce, ciphertext); err != nil {
		return fmt.Errorf("queue confirmation resend: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit confirmation resend: %w", err)
	}

	return nil
}

// ConfirmRegistration consumes the token and sets a password chosen by the email owner.
// The account remains disabled until the profile is provisioned.
func (s *Store) ConfirmRegistration(ctx context.Context, token, password string) (uuid.UUID, string, error) {
	if !s.allowedPassword(password) {
		return uuid.Nil, "", ErrInvalidPassword
	}

	if len(token) != 43 {
		return uuid.Nil, "", ErrInvalidConfirmation
	}

	decoded, err := base64.RawURLEncoding.DecodeString(token)

	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != token {
		return uuid.Nil, "", ErrInvalidConfirmation
	}

	hash := sha256.Sum256([]byte(token))
	var pending bool
	const find = `SELECT EXISTS (SELECT 1 FROM registrations
		WHERE token_hash = $1 AND confirmed_at IS NULL AND expires_at > statement_timestamp())`
	if err := s.db.QueryRowContext(ctx, find, hash[:]).Scan(&pending); err != nil {
		return uuid.Nil, "", fmt.Errorf("look up registration token: %w", err)
	}
	if !pending {
		return uuid.Nil, "", ErrInvalidConfirmation
	}

	var salt [16]byte

	if _, err := rand.Read(salt[:]); err != nil {
		return uuid.Nil, "", fmt.Errorf("generate password salt: %w", err)
	}

	passwordHash, err := s.hashPasswordVersion(ctx, s.newPasswordVersion(), password, salt[:])

	if err != nil {
		return uuid.Nil, "", fmt.Errorf("hash password: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)

	if err != nil {
		return uuid.Nil, "", fmt.Errorf("begin confirmation: %w", err)
	}

	defer tx.Rollback()

	var id uuid.UUID
	const lock = `SELECT user_id FROM registrations WHERE token_hash = $1 AND confirmed_at IS NULL FOR UPDATE`
	if err := tx.QueryRowContext(ctx, lock, hash[:]).Scan(&id); errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, "", ErrInvalidConfirmation
	} else if err != nil {
		return uuid.Nil, "", fmt.Errorf("lock registration confirmation: %w", err)
	}

	const query = `UPDATE registrations SET confirmed_at = clock_timestamp()
		WHERE user_id = $1 AND expires_at > clock_timestamp()
		RETURNING nickname`

	var nickname string
	err = tx.QueryRowContext(ctx, query, id).Scan(&nickname)

	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, "", ErrInvalidConfirmation
	}

	if err != nil {
		return uuid.Nil, "", fmt.Errorf("confirm registration: %w", err)
	}

	const setPassword = `UPDATE credentials SET password_salt = $1, password_hash = $2,
		password_version = $4, password_revision = password_revision + 1, email_verified = true
		WHERE user_id = $3 AND NOT enabled`

	result, err := tx.ExecContext(ctx, setPassword, salt[:], passwordHash, id, s.newPasswordVersion())

	if err != nil {
		return uuid.Nil, "", fmt.Errorf("set registration password: %w", err)
	}

	count, err := result.RowsAffected()

	if err != nil || count != 1 {
		return uuid.Nil, "", errors.New("registration credentials unavailable")
	}

	if err := tx.Commit(); err != nil {
		return uuid.Nil, "", fmt.Errorf("commit registration confirmation: %w", err)
	}

	return id, nickname, nil
}

// CleanupExpiredRegistrations only removes unconfirmed, disabled accounts.
func (s *Store) CleanupExpiredRegistrations(ctx context.Context) error {
	const query = `WITH expired AS (
		SELECT r.user_id FROM registrations r JOIN credentials c ON c.user_id = r.user_id
		WHERE r.confirmed_at IS NULL AND r.expires_at <= CURRENT_TIMESTAMP AND NOT c.enabled
		ORDER BY r.expires_at, r.user_id
		LIMIT 100 FOR UPDATE OF r, c SKIP LOCKED
	)
	DELETE FROM credentials WHERE user_id IN (SELECT user_id FROM expired) AND NOT enabled`

	if _, err := s.db.ExecContext(ctx, query); err != nil {
		return fmt.Errorf("cleanup expired registrations: %w", err)
	}

	return nil
}
