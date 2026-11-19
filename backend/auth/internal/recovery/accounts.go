package recovery

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

var ErrInconsistent = errors.New("auth and user snapshots are inconsistent")

// AccountIssue keeps the identifier out of error text and normal logs.
type AccountIssue struct {
	UserID uuid.UUID `json:"user_id"`
	Kind   string    `json:"kind"`
}

func (issue *AccountIssue) Error() string {
	return ErrInconsistent.Error()
}

func (issue *AccountIssue) Unwrap() error {
	return ErrInconsistent
}

type AccountCheck struct {
	Accounts int64
	Pending  int64
}

type authAccount struct {
	id         uuid.UUID
	enabled    bool
	registered bool
	confirmed  bool
	hasRole    bool
	lifecycle  sql.NullString
	deletedAt  sql.NullTime
}

type userProfile struct {
	id        uuid.UUID
	active    bool
	archived  bool
	deletedAt sql.NullTime
}

// CheckAccounts compares isolated, read-only snapshots; it cannot prove that
// either backup includes changes made after its recovery point.
func CheckAccounts(ctx context.Context, auth, users *sql.DB) (AccountCheck, error) {
	var result AccountCheck

	authTx, err := auth.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return result, fmt.Errorf("open auth snapshot: %w", err)
	}

	defer authTx.Rollback()

	userTx, err := users.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return result, fmt.Errorf("open user snapshot: %w", err)
	}

	defer userTx.Rollback()

	authRows, err := authTx.QueryContext(ctx, `SELECT c.user_id, c.enabled, r.user_id IS NOT NULL,
		r.confirmed_at IS NOT NULL, EXISTS (SELECT 1 FROM account_roles role WHERE role.user_id = c.user_id),
		d.state, d.deleted_at
		FROM credentials c LEFT JOIN registrations r ON r.user_id = c.user_id
		LEFT JOIN account_deletions d ON d.user_id = c.user_id ORDER BY c.user_id`)
	if err != nil {
		return result, fmt.Errorf("read auth accounts: %w", err)
	}

	defer authRows.Close()

	userRows, err := userTx.QueryContext(ctx, `SELECT COALESCE(u.id, d.id), u.id IS NOT NULL, d.id IS NOT NULL, d.deleted_at
		FROM users u FULL OUTER JOIN deleted_users d ON d.id = u.id ORDER BY 1`)
	if err != nil {
		return result, fmt.Errorf("read user profiles: %w", err)
	}

	defer userRows.Close()

	var account authAccount
	var profile userProfile
	moreAuth := authRows.Next()
	moreUser := userRows.Next()

	for moreAuth || moreUser {
		if err := ctx.Err(); err != nil {
			return result, err
		}

		if moreAuth {
			if err := authRows.Scan(&account.id, &account.enabled, &account.registered, &account.confirmed, &account.hasRole, &account.lifecycle, &account.deletedAt); err != nil {
				return result, fmt.Errorf("scan auth account: %w", err)
			}
		}

		if moreUser {
			if err := userRows.Scan(&profile.id, &profile.active, &profile.archived, &profile.deletedAt); err != nil {
				return result, fmt.Errorf("scan user profile: %w", err)
			}
		}

		if moreUser && (!moreAuth || bytes.Compare(profile.id[:], account.id[:]) < 0) {
			return result, &AccountIssue{UserID: profile.id, Kind: "profile_without_credentials"}
		}

		if !moreAuth {
			break
		}

		matched := moreUser && account.id == profile.id
		pending, valid := accountMatches(account, profile, matched)
		if !valid {
			return result, &AccountIssue{UserID: account.id, Kind: "account_profile_mismatch"}
		}

		result.Accounts++
		if pending {
			result.Pending++
		}

		moreAuth = authRows.Next()
		if matched {
			moreUser = userRows.Next()
		}
	}

	if err := authRows.Err(); err != nil {
		return result, fmt.Errorf("iterate auth accounts: %w", err)
	}

	if err := userRows.Err(); err != nil {
		return result, fmt.Errorf("iterate user profiles: %w", err)
	}

	if err := authRows.Close(); err != nil {
		return result, err
	}

	if err := userRows.Close(); err != nil {
		return result, err
	}

	if err := checkPendingOperations(ctx, authTx, userTx); err != nil {
		return result, err
	}

	if err := checkPendingRegistrations(ctx, authTx, userTx); err != nil {
		return result, err
	}

	if err := authTx.Commit(); err != nil {
		return result, fmt.Errorf("close auth snapshot: %w", err)
	}

	if err := userTx.Commit(); err != nil {
		return result, fmt.Errorf("close user snapshot: %w", err)
	}

	return result, nil
}

func accountMatches(a authAccount, p userProfile, matched bool) (pending, valid bool) {
	if a.id == uuid.Nil || (matched && (p.id == uuid.Nil || p.active == p.archived)) {
		return false, false
	}

	if a.registered {
		return true, !a.enabled && !a.lifecycle.Valid && (!matched || (p.active && a.confirmed))
	}

	if !a.lifecycle.Valid {
		return false, matched && p.active
	}

	if a.enabled || a.hasRole || !a.deletedAt.Valid {
		return false, false
	}

	if matched && p.archived && (!p.deletedAt.Valid || !p.deletedAt.Time.Equal(a.deletedAt.Time)) {
		return false, false
	}

	switch a.lifecycle.String {
	case "deleting", "restoring_owner", "restoring_moderator":
		return true, matched
	case "deleted":
		return false, matched && p.archived
	case "purging":
		return true, !matched || p.archived
	default:
		return false, false
	}
}

// Pending operations can only be retried safely if the user's idempotency record
// agrees with the already-applied profile state and the original auth request.
func checkPendingOperations(ctx context.Context, auth, users *sql.Tx) error {
	rows, err := auth.QueryContext(ctx, `SELECT user_id, operation_id, state, deleted_at FROM account_deletions
		WHERE state IN ('deleting', 'restoring_owner', 'restoring_moderator', 'purging') ORDER BY user_id`)
	if err != nil {
		return fmt.Errorf("read pending account operations: %w", err)
	}

	defer rows.Close()

	type operation struct {
		userID      uuid.UUID
		operationID uuid.UUID
		state       string
		deletedAt   time.Time
	}

	const batchSize = 200
	for {
		batch := make([]operation, 0, batchSize)
		userIDs := make([]string, 0, batchSize)
		operationIDs := make([]string, 0, batchSize)

		for len(batch) < batchSize && rows.Next() {
			var item operation
			if err := rows.Scan(&item.userID, &item.operationID, &item.state, &item.deletedAt); err != nil {
				return fmt.Errorf("scan pending account operation: %w", err)
			}
			batch = append(batch, item)
			userIDs = append(userIDs, item.userID.String())
			operationIDs = append(operationIDs, item.operationID.String())
		}

		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate pending account operations: %w", err)
		}

		if len(batch) == 0 {
			break
		}

		proofs, err := users.QueryContext(ctx, `SELECT req.ordinality,
			EXISTS (SELECT 1 FROM users u WHERE u.id = req.user_id),
			EXISTS (SELECT 1 FROM deleted_users d WHERE d.id = req.user_id),
			o.user_id, o.operation, o.deleted_at
			FROM unnest($1::uuid[], $2::uuid[]) WITH ORDINALITY AS req(user_id, operation_id, ordinality)
			LEFT JOIN account_lifecycle_operations o ON o.operation_id = req.operation_id
			ORDER BY req.ordinality`, pq.Array(userIDs), pq.Array(operationIDs))
		if err != nil {
			return fmt.Errorf("read user operation proofs: %w", err)
		}

		index := 0
		for proofs.Next() {
			var ordinal int64
			var active, archived bool
			var recordedUser uuid.NullUUID
			var recordedOperation sql.NullString
			var recordedAt sql.NullTime

			if err := proofs.Scan(&ordinal, &active, &archived, &recordedUser, &recordedOperation, &recordedAt); err != nil {
				proofs.Close()
				return fmt.Errorf("scan user operation proof: %w", err)
			}
			if index >= len(batch) || ordinal != int64(index+1) {
				proofs.Close()
				return ErrInconsistent
			}

			item := batch[index]
			index++
			recorded := recordedUser.Valid
			valid := !recorded || (recordedUser.UUID == item.userID && recordedOperation.Valid &&
				recordedOperation.String == item.state && recordedAt.Valid && recordedAt.Time.Equal(item.deletedAt))

			switch item.state {
			case "deleting":
				valid = valid && recorded == archived
			case "restoring_owner", "restoring_moderator":
				valid = valid && recorded == active
			case "purging":
				valid = valid && !recorded
			default:
				valid = false
			}

			if !valid {
				proofs.Close()
				return &AccountIssue{UserID: item.userID, Kind: "lifecycle_proof_mismatch"}
			}
		}

		if err := proofs.Err(); err != nil {
			proofs.Close()
			return fmt.Errorf("iterate user operation proofs: %w", err)
		}

		if err := proofs.Close(); err != nil {
			return err
		}

		if index != len(batch) {
			return ErrInconsistent
		}
	}

	return rows.Close()
}

func checkPendingRegistrations(ctx context.Context, auth, users *sql.Tx) error {
	rows, err := auth.QueryContext(ctx, `SELECT user_id, nickname FROM registrations ORDER BY user_id`)
	if err != nil {
		return fmt.Errorf("read pending registrations: %w", err)
	}

	defer rows.Close()

	type registration struct {
		id       uuid.UUID
		nickname string
	}

	const batchSize = 200
	for {
		batch := make([]registration, 0, batchSize)
		userIDs := make([]string, 0, batchSize)

		for len(batch) < batchSize && rows.Next() {
			var item registration

			if err := rows.Scan(&item.id, &item.nickname); err != nil {
				return fmt.Errorf("scan pending registration: %w", err)
			}
			batch = append(batch, item)
			userIDs = append(userIDs, item.id.String())
		}

		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate pending registrations: %w", err)
		}

		if len(batch) == 0 {
			break
		}

		proofs, err := users.QueryContext(ctx, `SELECT req.ordinality,
			EXISTS (SELECT 1 FROM users u WHERE u.id = req.user_id), p.nickname
			FROM unnest($1::uuid[]) WITH ORDINALITY AS req(user_id, ordinality)
			LEFT JOIN registration_provisions p ON p.user_id = req.user_id
			ORDER BY req.ordinality`, pq.Array(userIDs))
		if err != nil {
			return fmt.Errorf("read registration proofs: %w", err)
		}

		index := 0
		for proofs.Next() {
			var ordinal int64
			var active bool
			var original sql.NullString

			if err := proofs.Scan(&ordinal, &active, &original); err != nil {
				proofs.Close()
				return fmt.Errorf("scan registration proof: %w", err)
			}
			if index >= len(batch) || ordinal != int64(index+1) {
				proofs.Close()
				return ErrInconsistent
			}

			item := batch[index]
			index++

			if active != original.Valid || (original.Valid && original.String != item.nickname) {
				proofs.Close()
				return &AccountIssue{UserID: item.id, Kind: "registration_proof_mismatch"}
			}
		}

		if err := proofs.Err(); err != nil {
			proofs.Close()
			return fmt.Errorf("iterate registration proofs: %w", err)
		}

		if err := proofs.Close(); err != nil {
			return err
		}

		if index != len(batch) {
			return ErrInconsistent
		}
	}

	return rows.Close()
}
