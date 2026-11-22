package credentials

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/mail"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

var ErrEmailUnavailable = errors.New("email unavailable")

func (s *Store) RequestEmailChange(ctx context.Context, userID, sessionID uuid.UUID, revision int64, sessionHash [32]byte, address string, key []byte) error {
	email := strings.ToLower(strings.TrimSpace(address))
	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Address != email || len(email) > 254 || strings.Count(email, "@") != 1 {
		return ErrInvalidAccountDetails
	}

	aead, err := registrationAEAD(key)
	if err != nil {
		return err
	}
	id, err := uuid.NewRandom()
	if err != nil {
		return err
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return err
	}

	token := base64.RawURLEncoding.EncodeToString(secret[:])
	hash := sha256.Sum256([]byte(token))
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ciphertext := aead.Seal(nil, nonce, []byte(token), id[:])

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var currentEmail string
	err = tx.QueryRowContext(ctx, `SELECT email FROM credentials WHERE user_id=$1 AND enabled AND password_revision=$2 FOR UPDATE`, userID, revision).Scan(&currentEmail)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInvalidCredentials
	}
	if err != nil {
		return err
	}
	if err := lockEmailChangeSession(ctx, tx, userID, sessionID, sessionHash); err != nil {
		return err
	}
	if currentEmail == email {
		return ErrInvalidAccountDetails
	}

	if _, err = tx.ExecContext(ctx, `DELETE FROM password_resets WHERE user_id=$1 AND purpose='change_email'`, userID); err != nil {
		return err
	}
	const insert = `INSERT INTO password_resets(id,user_id,email,pending_email,password_revision,token_hash,token_nonce,token_ciphertext,expires_at,purpose)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,clock_timestamp()+INTERVAL '1 hour','change_email')`
	if _, err = tx.ExecContext(ctx, insert, id, userID, currentEmail, email, revision, hash[:], nonce, ciphertext); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ConfirmEmailChange(ctx context.Context, userID, sessionID uuid.UUID, sessionHash [32]byte, token string) error {
	if len(token) != 43 {
		return ErrInvalidConfirmation
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(decoded) != 32 {
		return ErrInvalidConfirmation
	}
	hash := sha256.Sum256([]byte(token))

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var email string
	var revision int64
	err = tx.QueryRowContext(ctx, `SELECT email,password_revision FROM credentials WHERE user_id=$1 AND enabled FOR UPDATE`, userID).Scan(&email, &revision)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInvalidCredentials
	}
	if err != nil {
		return err
	}
	if err = lockEmailChangeSession(ctx, tx, userID, sessionID, sessionHash); err != nil {
		return err
	}

	valid, err := lockUnexpiredEmailToken(ctx, tx, userID, hash, revision, email, "change_email")
	if err != nil {
		return err
	}
	if !valid {
		return ErrInvalidConfirmation
	}

	const update = `UPDATE credentials c SET email=p.pending_email,email_verified=true,password_revision=c.password_revision+1
		FROM password_resets p WHERE c.user_id=$1 AND p.user_id=c.user_id AND p.token_hash=$2 AND p.purpose='change_email'`
	if _, err = tx.ExecContext(ctx, update, userID, hash[:]); err != nil {
		var pg *pq.Error
		if errors.As(err, &pg) && pg.Code == "23505" {
			return ErrEmailUnavailable
		}
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE sessions SET revoked_at=clock_timestamp() WHERE user_id=$1 AND revoked_at IS NULL`, userID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM password_resets WHERE user_id=$1`, userID); err != nil {
		return err
	}
	return tx.Commit()
}

func lockEmailChangeSession(ctx context.Context, tx *sql.Tx, userID, sessionID uuid.UUID, hash [32]byte) error {
	var locked uuid.UUID
	err := tx.QueryRowContext(ctx, `SELECT id FROM sessions WHERE user_id=$1 AND id=$2 FOR UPDATE`, userID, sessionID).Scan(&locked)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInvalidCredentials
	}
	if err != nil {
		return err
	}
	return checkLockedSessionDeadline(ctx, tx, userID, sessionID, hash)
}
