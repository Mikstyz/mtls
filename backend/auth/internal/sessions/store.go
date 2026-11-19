package sessions

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

var ErrInvalidSession = errors.New("invalid or expired session")
var ErrInvalidDevice = errors.New("invalid device name")

type Store struct {
	db    *sql.DB
	cache Cache
}

// Cache supplies lookup hints only; PostgreSQL verifies every session.
type Cache interface {
	Lookup(context.Context, [32]byte) (uuid.UUID, bool, error)
	Remember(context.Context, [32]byte, uuid.UUID) error
}

func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// SetCache is called before the store is used concurrently.
func (s *Store) SetCache(cache Cache) {
	s.cache = cache
}

type Session struct {
	ID         uuid.UUID `json:"id"`
	DeviceName string    `json:"device_name"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Online     bool      `json:"online"`
	IsCurrent  bool      `json:"is_current"`
}

type Identity struct {
	UserID    uuid.UUID
	SessionID uuid.UUID
	TokenHash [32]byte `json:"-"`
}

// Create must be called only after successful authentication.
func (s *Store) Create(ctx context.Context, userID uuid.UUID, passwordRevision int64, deviceName string) (string, error) {
	return s.create(ctx, userID, passwordRevision, deviceName, nil)
}

// CreateWithRecovery consumes an email proof atomically with the new session.
func (s *Store) CreateWithRecovery(ctx context.Context, userID uuid.UUID, passwordRevision int64, deviceName string, proofHash [32]byte) (string, error) {
	return s.create(ctx, userID, passwordRevision, deviceName, &proofHash)
}

func (s *Store) create(ctx context.Context, userID uuid.UUID, passwordRevision int64, deviceName string, proofHash *[32]byte) (string, error) {
	deviceName = strings.TrimSpace(deviceName)

	if userID == uuid.Nil || !utf8.ValidString(deviceName) || utf8.RuneCountInString(deviceName) == 0 || utf8.RuneCountInString(deviceName) > 128 {
		return "", ErrInvalidDevice
	}

	var secret [32]byte

	if _, err := rand.Read(secret[:]); err != nil {
		return "", fmt.Errorf("generate session token: %w", err)
	}

	token := base64.RawURLEncoding.EncodeToString(secret[:])
	hash := sha256.Sum256([]byte(token))
	id, err := uuid.NewRandom()

	if err != nil {
		return "", fmt.Errorf("generate session id: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)

	if err != nil {
		return "", fmt.Errorf("begin session creation: %w", err)
	}

	defer tx.Rollback()

	const lockCredentials = `SELECT 1 FROM credentials
		WHERE user_id = $1 AND password_revision = $2 AND enabled FOR SHARE`

	var valid int
	err = tx.QueryRowContext(ctx, lockCredentials, userID, passwordRevision).Scan(&valid)

	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrInvalidSession
	}

	if err != nil {
		return "", fmt.Errorf("check credentials: %w", err)
	}

	var recoveryID uuid.UUID

	if proofHash != nil {
		const lockProof = `SELECT p.id FROM password_resets p JOIN credentials c ON c.user_id = p.user_id
			WHERE p.user_id = $1 AND p.token_hash = $2 AND p.purpose = 'password_reset'
				AND p.password_revision = $3 AND c.email_verified AND p.email = c.email
			FOR UPDATE OF p`

		err = tx.QueryRowContext(ctx, lockProof, userID, proofHash[:], passwordRevision).Scan(&recoveryID)

		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrInvalidSession
		}

		if err != nil {
			return "", fmt.Errorf("lock recovery login proof: %w", err)
		}

		var unexpired bool

		if err := tx.QueryRowContext(ctx, `SELECT expires_at > clock_timestamp() FROM password_resets WHERE id = $1`, recoveryID).Scan(&unexpired); err != nil {
			return "", fmt.Errorf("check recovery login deadline: %w", err)
		}

		if !unexpired {
			return "", ErrInvalidSession
		}
	}

	const query = `
		INSERT INTO sessions (id, user_id, token_hash, device_name, expires_at, recovery_generation)
		SELECT $1, $2, $3, $4, CURRENT_TIMESTAMP + INTERVAL '720 hours', generation
		FROM session_epoch WHERE id
	`

	result, err := tx.ExecContext(ctx, query, id, userID, hash[:], deviceName)

	if err != nil {
		return "", fmt.Errorf("create session: %w", err)
	}

	count, err := result.RowsAffected()

	if err != nil || count != 1 {
		return "", errors.New("session recovery generation unavailable")
	}

	if proofHash != nil {
		if _, err := tx.ExecContext(ctx, `DELETE FROM password_resets WHERE id = $1`, recoveryID); err != nil {
			return "", fmt.Errorf("consume recovery login proof: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit session: %w", err)
	}

	if s.cache != nil {
		_ = s.cache.Remember(ctx, hash, id)
	}

	return token, nil
}

// Authenticate verifies a session and records its latest authenticated activity.
func (s *Store) Authenticate(ctx context.Context, token string) (Identity, error) {
	if len(token) != 43 {
		return Identity{}, ErrInvalidSession
	}

	decoded, err := base64.RawURLEncoding.DecodeString(token)

	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != token {
		return Identity{}, ErrInvalidSession
	}

	hash := sha256.Sum256([]byte(token))
	var cachedID uuid.UUID
	var cacheHit bool

	if s.cache != nil {
		var cacheErr error
		cachedID, cacheHit, cacheErr = s.cache.Lookup(ctx, hash)

		if cacheErr != nil || cachedID == uuid.Nil {
			cacheHit = false
		}
	}

	tx, err := s.db.BeginTx(ctx, nil)

	if err != nil {
		return Identity{}, fmt.Errorf("begin session authentication: %w", err)
	}

	defer tx.Rollback()

	var sessionID uuid.UUID

	if cacheHit {
		err = tx.QueryRowContext(ctx, `SELECT id FROM sessions WHERE id = $1 AND token_hash = $2 FOR UPDATE`, cachedID, hash[:]).Scan(&sessionID)

		if errors.Is(err, sql.ErrNoRows) {
			cacheHit = false
		}
	}

	if !cacheHit {
		err = tx.QueryRowContext(ctx, `SELECT id FROM sessions WHERE token_hash = $1 FOR UPDATE`, hash[:]).Scan(&sessionID)
	}

	if errors.Is(err, sql.ErrNoRows) {
		return Identity{}, ErrInvalidSession
	}

	if err != nil {
		return Identity{}, fmt.Errorf("lock session: %w", err)
	}

	// Evaluate expiry after acquiring the lock, not before a potentially long wait.
	const query = `
		UPDATE sessions SET last_seen_at = clock_timestamp()
		FROM credentials
		WHERE sessions.id = $1 AND sessions.token_hash = $2 AND sessions.revoked_at IS NULL
			AND sessions.recovery_generation = (SELECT generation FROM session_epoch WHERE id)
			AND sessions.expires_at > clock_timestamp()
			AND sessions.last_seen_at > clock_timestamp() - INTERVAL '168 hours'
			AND credentials.user_id = sessions.user_id AND credentials.enabled
		RETURNING sessions.user_id, sessions.id
	`

	var identity Identity
	err = tx.QueryRowContext(ctx, query, sessionID, hash[:]).Scan(&identity.UserID, &identity.SessionID)

	if errors.Is(err, sql.ErrNoRows) {
		return Identity{}, ErrInvalidSession
	}

	if err != nil {
		return Identity{}, fmt.Errorf("authenticate session: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return Identity{}, fmt.Errorf("commit session authentication: %w", err)
	}

	if s.cache != nil && !cacheHit {
		_ = s.cache.Remember(ctx, hash, sessionID)
	}

	identity.TokenHash = hash
	return identity, nil
}

// List returns only active sessions owned by userID.
func (s *Store) List(ctx context.Context, identity Identity, offset int) ([]Session, bool, error) {
	if offset < 0 {
		return nil, false, errors.New("invalid session offset")
	}
	tx, err := s.beginAuthorizedSession(ctx, identity)

	if err != nil {
		return nil, false, err
	}

	defer tx.Rollback()

	const query = `
		SELECT id, device_name, created_at, last_seen_at, expires_at,
			last_seen_at > CURRENT_TIMESTAMP - INTERVAL '2 minutes'
		FROM sessions
		WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > CURRENT_TIMESTAMP
			AND recovery_generation = (SELECT generation FROM session_epoch WHERE id)
			AND last_seen_at > CURRENT_TIMESTAMP - INTERVAL '168 hours'
		ORDER BY created_at DESC, id
		LIMIT 101 OFFSET $2
	`

	rows, err := tx.QueryContext(ctx, query, identity.UserID, offset)

	if err != nil {
		return nil, false, fmt.Errorf("list sessions: %w", err)
	}

	defer rows.Close()

	sessions := make([]Session, 0)

	for rows.Next() {
		var session Session

		if err := rows.Scan(&session.ID, &session.DeviceName, &session.CreatedAt, &session.LastSeenAt, &session.ExpiresAt, &session.Online); err != nil {
			return nil, false, fmt.Errorf("scan session: %w", err)
		}

		session.IsCurrent = session.ID == identity.SessionID
		sessions = append(sessions, session)
	}

	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("list sessions: %w", err)
	}

	if err := rows.Close(); err != nil {
		return nil, false, fmt.Errorf("close session list: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("commit session list: %w", err)
	}

	hasMore := len(sessions) > 100

	if hasMore {
		sessions = sessions[:100]
	}

	return sessions, hasMore, nil
}

// Revoke only affects a session belonging to the authenticated user.
func (s *Store) Revoke(ctx context.Context, identity Identity, sessionID uuid.UUID) error {
	tx, err := s.beginAuthorizedSession(ctx, identity)

	if err != nil {
		return err
	}

	defer tx.Rollback()

	const query = `UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP
		WHERE user_id = $1 AND id = $2 AND revoked_at IS NULL`

	result, err := tx.ExecContext(ctx, query, identity.UserID, sessionID)

	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}

	count, err := result.RowsAffected()

	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}

	if count == 0 {
		return sql.ErrNoRows
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit session revocation: %w", err)
	}

	return nil
}

func (s *Store) RevokeOthers(ctx context.Context, identity Identity) error {
	tx, err := s.beginAuthorizedSession(ctx, identity)

	if err != nil {
		return err
	}

	defer tx.Rollback()

	const query = `UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP
		WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL`

	if _, err := tx.ExecContext(ctx, query, identity.UserID, identity.SessionID); err != nil {
		return fmt.Errorf("revoke other sessions: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit other session revocations: %w", err)
	}

	return nil
}

// Lock credentials before sessions, matching password changes and account deletion.
func (s *Store) beginAuthorizedSession(ctx context.Context, identity Identity) (*sql.Tx, error) {
	tx, err := s.db.BeginTx(ctx, nil)

	if err != nil {
		return nil, fmt.Errorf("begin session authorization: %w", err)
	}

	var found int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM credentials WHERE user_id = $1 AND enabled FOR UPDATE`, identity.UserID).Scan(&found)

	if err == nil {
		err = tx.QueryRowContext(ctx, `SELECT 1 FROM sessions WHERE user_id = $1 AND id = $2 FOR UPDATE`, identity.UserID, identity.SessionID).Scan(&found)
	}

	if errors.Is(err, sql.ErrNoRows) {
		_ = tx.Rollback()
		return nil, ErrInvalidSession
	}

	if err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("lock session authorization: %w", err)
	}

	const valid = `SELECT revoked_at IS NULL AND expires_at > clock_timestamp()
		AND recovery_generation = (SELECT generation FROM session_epoch WHERE id)
		AND last_seen_at > clock_timestamp() - INTERVAL '168 hours' AND token_hash = $3
		FROM sessions WHERE user_id = $1 AND id = $2`

	var active bool
	err = tx.QueryRowContext(ctx, valid, identity.UserID, identity.SessionID, identity.TokenHash[:]).Scan(&active)

	if err != nil || !active {
		_ = tx.Rollback()

		if err != nil {
			return nil, fmt.Errorf("check session authorization: %w", err)
		}

		return nil, ErrInvalidSession
	}

	return tx, nil
}

// RevokeAll must be called when an account is disabled or deleted.
func (s *Store) RevokeAll(ctx context.Context, userID uuid.UUID) error {
	const query = `UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP
		WHERE user_id = $1 AND revoked_at IS NULL`

	if _, err := s.db.ExecContext(ctx, query, userID); err != nil {
		return fmt.Errorf("revoke all sessions: %w", err)
	}

	return nil
}

type Presence struct {
	Active     bool       `json:"active"`
	Online     bool       `json:"online"`
	LastOnline *time.Time `json:"last_online"`
}

// UserPresence derives online status from active, non-revoked sessions.
func (s *Store) UserPresence(ctx context.Context, userID uuid.UUID) (Presence, error) {
	const query = `
		SELECT EXISTS (SELECT 1 FROM credentials c WHERE c.user_id = $1 AND c.enabled
			AND NOT EXISTS (SELECT 1 FROM account_deletions d WHERE d.user_id = c.user_id)),
			COALESCE(BOOL_OR(credentials.enabled AND sessions.revoked_at IS NULL
			AND NOT EXISTS (SELECT 1 FROM account_deletions d WHERE d.user_id = $1)
			AND sessions.recovery_generation = (SELECT generation FROM session_epoch WHERE id)
			AND sessions.expires_at > CURRENT_TIMESTAMP
			AND sessions.last_seen_at > CURRENT_TIMESTAMP - INTERVAL '2 minutes'), false),
			GREATEST(MAX(sessions.last_seen_at),
				(SELECT last_seen_at FROM user_session_history WHERE user_id = $1))
		FROM sessions JOIN credentials ON credentials.user_id = sessions.user_id
		WHERE sessions.user_id = $1
	`

	var presence Presence
	var lastSeen sql.NullTime

	if err := s.db.QueryRowContext(ctx, query, userID).Scan(&presence.Active, &presence.Online, &lastSeen); err != nil {
		return Presence{}, fmt.Errorf("get session presence: %w", err)
	}

	if lastSeen.Valid {
		presence.LastOnline = &lastSeen.Time
	}

	return presence, nil
}

// CleanupExpiredSessions preserves last-online time while removing old session metadata.
func (s *Store) CleanupExpiredSessions(ctx context.Context) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)

	if err != nil {
		return 0, fmt.Errorf("begin session cleanup: %w", err)
	}

	defer tx.Rollback()

	const deleteOrphans = `DELETE FROM sessions WHERE id IN (
		SELECT s.id FROM sessions s WHERE (s.revoked_at IS NOT NULL OR s.expires_at <= CURRENT_TIMESTAMP
			OR s.last_seen_at <= CURRENT_TIMESTAMP - INTERVAL '168 hours')
			AND NOT EXISTS (SELECT 1 FROM credentials c WHERE c.user_id = s.user_id)
		ORDER BY s.expires_at, s.id LIMIT 500 FOR UPDATE OF s SKIP LOCKED
	)`

	orphanResult, err := tx.ExecContext(ctx, deleteOrphans)

	if err != nil {
		return 0, fmt.Errorf("cleanup orphan sessions: %w", err)
	}

	orphanCount, err := orphanResult.RowsAffected()

	if err != nil {
		return 0, fmt.Errorf("count orphan sessions: %w", err)
	}

	const selectUser = `SELECT c.user_id FROM credentials c WHERE c.user_id IN (
		SELECT s.user_id FROM sessions s
		WHERE s.revoked_at IS NOT NULL OR s.expires_at <= CURRENT_TIMESTAMP
			OR s.last_seen_at <= CURRENT_TIMESTAMP - INTERVAL '168 hours'
		ORDER BY s.expires_at, s.id LIMIT 500
	) ORDER BY c.user_id LIMIT 100 FOR UPDATE OF c SKIP LOCKED`

	rows, err := tx.QueryContext(ctx, selectUser)

	if err != nil {
		return 0, fmt.Errorf("select sessions for cleanup: %w", err)
	}

	var users []string

	for rows.Next() {
		var id uuid.UUID

		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan sessions for cleanup: %w", err)
		}

		users = append(users, id.String())
	}

	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("read sessions for cleanup: %w", err)
	}

	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("close sessions for cleanup: %w", err)
	}

	if len(users) == 0 {
		if err := tx.Commit(); err != nil {
			return 0, fmt.Errorf("commit session cleanup: %w", err)
		}

		return orphanCount, nil
	}

	const query = `WITH removed AS (
		DELETE FROM sessions WHERE id IN (
			SELECT id FROM sessions WHERE user_id = ANY($1::uuid[])
				AND (revoked_at IS NOT NULL OR expires_at <= CURRENT_TIMESTAMP
					OR last_seen_at <= CURRENT_TIMESTAMP - INTERVAL '168 hours')
			ORDER BY expires_at, id LIMIT 500 FOR UPDATE SKIP LOCKED
		) RETURNING user_id, last_seen_at
	)
	INSERT INTO user_session_history (user_id, last_seen_at)
	SELECT user_id, MAX(last_seen_at) FROM removed GROUP BY user_id
	ON CONFLICT (user_id) DO UPDATE SET last_seen_at = GREATEST(user_session_history.last_seen_at, EXCLUDED.last_seen_at)`

	result, err := tx.ExecContext(ctx, query, pq.Array(users))

	if err != nil {
		return 0, fmt.Errorf("cleanup expired sessions: %w", err)
	}

	count, err := result.RowsAffected()

	if err != nil {
		return 0, fmt.Errorf("count cleaned users: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit session cleanup: %w", err)
	}

	return count + orphanCount, nil
}
