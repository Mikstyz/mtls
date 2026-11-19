package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"mtls/user/internal/models"
)

type userRepo struct {
	db *sql.DB
}

var ErrProvisionConflict = errors.New("registration provision conflict")

// ProvisionUser records the registration request and creates its profile atomically.
// A retry must not recreate a profile that was subsequently deleted.
func (r *userRepo) ProvisionUser(ctx context.Context, id uuid.UUID, nickname string, validUntil time.Time) error {
	if id == uuid.Nil || validUntil.IsZero() {
		return ErrProvisionConflict
	}

	tx, err := r.db.BeginTx(ctx, nil)

	if err != nil {
		return fmt.Errorf("begin user provision: %w", err)
	}

	defer tx.Rollback()

	if err := lockUserLifecycle(ctx, tx, id); err != nil {
		return err
	}

	var valid bool
	const checkDeadline = `SELECT $1::timestamptz > clock_timestamp()
		AND $1::timestamptz <= clock_timestamp() + INTERVAL '5 minutes'`

	if err := tx.QueryRowContext(ctx, checkDeadline, validUntil).Scan(&valid); err != nil {
		return fmt.Errorf("check provision deadline: %w", err)
	}

	if !valid {
		return ErrProvisionConflict
	}

	const recordRequest = `INSERT INTO registration_provisions (user_id, nickname)
		VALUES ($1, $2) ON CONFLICT (user_id) DO NOTHING`

	result, err := tx.ExecContext(ctx, recordRequest, id, nickname)

	if err != nil {
		return fmt.Errorf("record user provision: %w", err)
	}

	count, err := result.RowsAffected()

	if err != nil {
		return fmt.Errorf("record user provision: %w", err)
	}

	if count == 0 {
		var originalNickname string
		var exists bool

		const lookup = `SELECT nickname, EXISTS (SELECT 1 FROM users WHERE id = $1)
			FROM registration_provisions WHERE user_id = $1`

		if err := tx.QueryRowContext(ctx, lookup, id).Scan(&originalNickname, &exists); err != nil {
			return fmt.Errorf("get user provision: %w", err)
		}

		if originalNickname != nickname || !exists {
			return ErrProvisionConflict
		}

		return tx.Commit()
	}

	const createUser = `INSERT INTO users (id, nickname, created_at)
		SELECT $1, $2, CURRENT_TIMESTAMP
		WHERE NOT EXISTS (SELECT 1 FROM deleted_users WHERE id = $1)`

	result, err = tx.ExecContext(ctx, createUser, id, nickname)

	if err != nil {
		return fmt.Errorf("create provisioned user: %w", err)
	}

	count, err = result.RowsAffected()

	if err != nil {
		return fmt.Errorf("create provisioned user: %w", err)
	}

	if count != 1 {
		return ErrProvisionConflict
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit user provision: %w", err)
	}

	return nil
}

func NewUserRepo(db *sql.DB) *userRepo {
	return &userRepo{db: db}
}

func (r *userRepo) GetById(ctx context.Context, id uuid.UUID) (*models.User, error) {
	const query = "SELECT id, nickname, created_at, last_online, presence_visibility FROM users WHERE id = $1"

	var user models.User

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&user.ID,
		&user.Nickname,
		&user.CreatedAt,
		&user.LastOnline,
		&user.PresenceVisibility,
	)

	if err != nil {
		return nil, fmt.Errorf("get user by id: %w", err)
	}

	return &user, nil
}

func (r *userRepo) UpdatePresenceVisibility(ctx context.Context, id uuid.UUID, visibility string) error {
	if visibility != "everyone" && visibility != "nobody" {
		return errors.New("invalid presence visibility")
	}

	result, err := r.db.ExecContext(ctx, `UPDATE users SET presence_visibility = $1 WHERE id = $2`, visibility, id)

	if err != nil {
		return fmt.Errorf("update presence visibility: %w", err)
	}

	if err := requireAffectedUser(result); err != nil {
		return fmt.Errorf("update presence visibility: %w", err)
	}

	return nil
}

func (r *userRepo) NewUser(ctx context.Context, user models.User) error {
	const query = `
		INSERT INTO users (id, nickname, created_at, last_online)
		VALUES ($1, $2, $3, $4)
	`

	_, err := r.db.ExecContext(ctx, query, user.ID, user.Nickname, user.CreatedAt, user.LastOnline)

	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}

	return nil
}

func (r *userRepo) UpdateUser(ctx context.Context, user models.User) error {
	const query = "UPDATE users SET nickname = $1 WHERE id = $2"

	result, err := r.db.ExecContext(ctx, query, user.Nickname, user.ID)

	if err != nil {
		return fmt.Errorf("update user: %w", err)
	}

	if err := requireAffectedUser(result); err != nil {
		return fmt.Errorf("update user: %w", err)
	}

	return nil
}

func (r *userRepo) OnlineUpdate(ctx context.Context, id uuid.UUID) error {
	const query = "UPDATE users SET last_online = CURRENT_TIMESTAMP WHERE id = $1"

	result, err := r.db.ExecContext(ctx, query, id)

	if err != nil {
		return fmt.Errorf("update user last online: %w", err)
	}

	if err := requireAffectedUser(result); err != nil {
		return fmt.Errorf("update user last online: %w", err)
	}

	return nil
}

func requireAffectedUser(result sql.Result) error {
	count, err := result.RowsAffected()

	if err != nil {
		return err
	}

	if count == 0 {
		return sql.ErrNoRows
	}

	return nil
}
