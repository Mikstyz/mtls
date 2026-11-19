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
	"net/mail"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

var ErrInvalidCredentials = errors.New("invalid credentials")
var ErrInvalidAccountDetails = errors.New("invalid account details")

var loginPattern = regexp.MustCompile(`^[a-z0-9_]{3,32}$`)

const (
	memory      = 19 * 1024
	iterations  = 2
	parallelism = 1
	keyLength   = 32
)

type Store struct {
	db                 *sql.DB
	hashSlots          chan struct{}
	passwordBlocklist  map[[32]byte]struct{}
	normalizePasswords bool
}

func NewStore(db *sql.DB) *Store {
	return &Store{db: db, hashSlots: make(chan struct{}, 4)}
}

// SetPasswordNormalization enables version 2 writes after all auth instances support it.
// Call before serving requests.
func (s *Store) SetPasswordNormalization(enabled bool) {
	s.normalizePasswords = enabled
}

func (s *Store) newPasswordVersion() int {
	if s.normalizePasswords {
		return 2
	}

	return 1
}

func (s *Store) hashPasswordVersion(ctx context.Context, version int, password string, salt []byte) ([]byte, error) {
	switch version {
	case 1:
	case 2:
		password = norm.NFC.String(password)
	default:
		return nil, errors.New("unsupported password version")
	}

	return s.hashPassword(ctx, password, salt)
}

// Create requires a user ID assigned by the user service.
func (s *Store) Create(ctx context.Context, userID uuid.UUID, login, email, password string) error {
	login, email, err := validateAccount(userID, login, email, password)

	if err != nil {
		return err
	}

	if !s.allowedPassword(password) {
		return ErrInvalidPassword
	}

	var salt [16]byte

	if _, err := rand.Read(salt[:]); err != nil {
		return fmt.Errorf("generate password salt: %w", err)
	}

	hash, err := s.hashPasswordVersion(ctx, s.newPasswordVersion(), password, salt[:])

	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	const query = `INSERT INTO credentials (user_id, login, email, password_salt, password_hash, password_version)
		VALUES ($1, $2, $3, $4, $5, $6)`

	if _, err := s.db.ExecContext(ctx, query, userID, login, email, salt[:], hash, s.newPasswordVersion()); err != nil {
		return fmt.Errorf("create credentials: %w", err)
	}

	return nil
}

func validateAccount(userID uuid.UUID, login, email, password string) (string, string, error) {
	login = strings.ToLower(strings.TrimSpace(login))
	email = strings.ToLower(strings.TrimSpace(email))
	address, err := mail.ParseAddress(email)

	if userID == uuid.Nil || !loginPattern.MatchString(login) || err != nil || address.Address != email || strings.Count(email, "@") != 1 || len(email) > 254 || !validPassword(password) {
		return "", "", ErrInvalidAccountDetails
	}

	return login, email, nil
}

// Verify returns the user ID after checking the login or email and password.
// The caller must enforce rate limiting before invoking this method.
func (s *Store) Verify(ctx context.Context, identifier, password string) (uuid.UUID, int64, error) {
	identifier = strings.ToLower(strings.TrimSpace(identifier))

	if len(identifier) == 0 || len(identifier) > 254 || len(password) > 1024 {
		return uuid.Nil, 0, ErrInvalidCredentials
	}

	const query = `SELECT user_id, password_version, password_revision, password_salt, password_hash, enabled FROM credentials
		WHERE login = $1 OR email = $1`

	var userID uuid.UUID
	var salt, hash []byte
	var version int
	var revision int64
	var enabled bool
	err := s.db.QueryRowContext(ctx, query, identifier).Scan(&userID, &version, &revision, &salt, &hash, &enabled)

	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, 0, fmt.Errorf("get credentials: %w", err)
	}

	found := err == nil

	if !found {
		salt = make([]byte, 16)
		hash = make([]byte, keyLength)
		version = 1
	}

	if found && version != 1 && version != 2 {
		return uuid.Nil, 0, errors.New("unsupported password version")
	}

	if len(salt) != 16 || len(hash) != keyLength {
		return uuid.Nil, 0, errors.New("invalid stored password data")
	}

	actual, err := s.hashPasswordVersion(ctx, version, password, salt)

	if err != nil {
		return uuid.Nil, 0, fmt.Errorf("verify password: %w", err)
	}

	if subtle.ConstantTimeCompare(actual, hash) != 1 || !found || !enabled {
		return uuid.Nil, 0, ErrInvalidCredentials
	}

	if version == 1 && s.normalizePasswords {
		normalizedHash := hash

		if !norm.NFC.IsNormalString(password) {
			normalizedHash, err = s.hashPasswordVersion(ctx, 2, password, salt)

			if err != nil {
				return uuid.Nil, 0, fmt.Errorf("upgrade password hash: %w", err)
			}
		}

		const upgrade = `UPDATE credentials SET password_hash = $1, password_version = 2
			WHERE user_id = $2 AND enabled AND password_version = 1 AND password_revision = $3
				AND password_salt = $4 AND password_hash = $5`

		if _, err := s.db.ExecContext(ctx, upgrade, normalizedHash, userID, revision, salt, hash); err != nil {
			return uuid.Nil, 0, fmt.Errorf("upgrade password version: %w", err)
		}
	}

	return userID, revision, nil
}

func (s *Store) hashPassword(ctx context.Context, password string, salt []byte) ([]byte, error) {
	select {
	case s.hashSlots <- struct{}{}:
		defer func() { <-s.hashSlots }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	return argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, keyLength), nil
}

var ErrInvalidPassword = errors.New("invalid new password")

func validPassword(password string) bool {
	if !utf8.ValidString(password) || len(password) > 1024 || utf8.RuneCountInString(password) < 15 {
		return false
	}

	switch strings.ToLower(password) {
	case "123456789012345", "1234567890123456", "12345678901234567890", "111111111111111", "passwordpassword", "qwertyuiopasdfgh", "iloveyouiloveyou":
		return false
	default:
		return true
	}
}

func (s *Store) allowedPassword(password string) bool {
	if !validPassword(password) {
		return false
	}

	if s.normalizePasswords {
		password = norm.NFC.String(password)

		if !validPassword(password) {
			return false
		}
	}

	hash := sha256.Sum256([]byte(strings.ToLower(password)))
	_, blocked := s.passwordBlocklist[hash]

	return !blocked
}

// ChangePassword verifies the current password and revokes other sessions.
func (s *Store) ChangePassword(ctx context.Context, userID, sessionID uuid.UUID, tokenHash [32]byte, currentPassword, newPassword string) (string, error) {
	if !s.allowedPassword(newPassword) {
		return "", ErrInvalidPassword
	}

	if len(currentPassword) > 1024 {
		return "", ErrInvalidCredentials
	}

	const query = `SELECT password_version, password_salt, password_hash FROM credentials WHERE user_id = $1`

	var version int
	var oldSalt, oldHash []byte
	err := s.db.QueryRowContext(ctx, query, userID).Scan(&version, &oldSalt, &oldHash)

	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrInvalidCredentials
	}

	if err != nil {
		return "", fmt.Errorf("get credentials: %w", err)
	}

	if (version != 1 && version != 2) || len(oldSalt) != 16 || len(oldHash) != keyLength {
		return "", errors.New("invalid stored password data")
	}

	actual, err := s.hashPasswordVersion(ctx, version, currentPassword, oldSalt)

	if err != nil {
		return "", fmt.Errorf("verify password: %w", err)
	}

	if subtle.ConstantTimeCompare(actual, oldHash) != 1 {
		return "", ErrInvalidCredentials
	}

	var newSalt [16]byte

	if _, err := rand.Read(newSalt[:]); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}

	newHash, err := s.hashPasswordVersion(ctx, s.newPasswordVersion(), newPassword, newSalt[:])

	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}

	var sessionSecret [32]byte

	if _, err := rand.Read(sessionSecret[:]); err != nil {
		return "", fmt.Errorf("generate session token: %w", err)
	}

	token := base64.RawURLEncoding.EncodeToString(sessionSecret[:])
	newTokenHash := sha256.Sum256([]byte(token))

	tx, err := s.db.BeginTx(ctx, nil)

	if err != nil {
		return "", fmt.Errorf("begin password change: %w", err)
	}

	defer tx.Rollback()

	const updatePassword = `UPDATE credentials SET password_salt = $1, password_hash = $2, password_version = $7, password_revision = password_revision + 1
		WHERE user_id = $3 AND password_version = $4 AND password_salt = $5 AND password_hash = $6 AND enabled`

	result, err := tx.ExecContext(ctx, updatePassword, newSalt[:], newHash, userID, version, oldSalt, oldHash, s.newPasswordVersion())

	if err != nil {
		return "", fmt.Errorf("update password: %w", err)
	}

	count, err := result.RowsAffected()

	if err != nil {
		return "", fmt.Errorf("update password: %w", err)
	}

	if count != 1 {
		return "", ErrInvalidCredentials
	}

	const lockSession = `SELECT 1 FROM sessions
		WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL
			AND expires_at > CURRENT_TIMESTAMP
			AND last_seen_at > CURRENT_TIMESTAMP - INTERVAL '168 hours'
		FOR UPDATE`

	var active int
	err = tx.QueryRowContext(ctx, lockSession, sessionID, userID).Scan(&active)

	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrInvalidCredentials
	}

	if err != nil {
		return "", fmt.Errorf("check session: %w", err)
	}

	if err := checkLockedSessionDeadline(ctx, tx, userID, sessionID, tokenHash); err != nil {
		return "", err
	}

	const rotateSession = `UPDATE sessions SET token_hash = $1 WHERE id = $2 AND user_id = $3`

	if _, err := tx.ExecContext(ctx, rotateSession, newTokenHash[:], sessionID, userID); err != nil {
		return "", fmt.Errorf("rotate session: %w", err)
	}

	const revokeOthers = `UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP
		WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL`

	if _, err := tx.ExecContext(ctx, revokeOthers, userID, sessionID); err != nil {
		return "", fmt.Errorf("revoke other sessions: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit password change: %w", err)
	}

	return token, nil
}

// Recheck time after locking: transaction timestamps do not advance while waiting.
func checkLockedSessionDeadline(ctx context.Context, tx *sql.Tx, userID, sessionID uuid.UUID, tokenHash [32]byte) error {
	const query = `SELECT EXISTS (SELECT 1 FROM sessions WHERE user_id = $1 AND id = $2
		AND revoked_at IS NULL AND expires_at > clock_timestamp()
		AND recovery_generation = (SELECT generation FROM session_epoch WHERE id)
		AND last_seen_at > clock_timestamp() - INTERVAL '168 hours' AND token_hash = $3)`

	var valid bool

	if err := tx.QueryRowContext(ctx, query, userID, sessionID, tokenHash[:]).Scan(&valid); err != nil {
		return fmt.Errorf("recheck session deadline: %w", err)
	}

	if !valid {
		return ErrInvalidCredentials
	}

	return nil
}
