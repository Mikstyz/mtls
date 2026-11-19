package searchindex

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
)

// RebuildOffline replaces the user index through the outbox. All user publishers
// and search writers must be stopped and isolated until the operation succeeds.
func RebuildOffline(ctx context.Context, source, index *sql.DB) (int64, error) {
	if source == nil || index == nil {
		return 0, errors.New("both databases are required")
	}

	userTx, err := source.BeginTx(ctx, nil)

	if err != nil {
		return 0, fmt.Errorf("begin user rebuild transaction: %w", err)
	}

	defer userTx.Rollback()

	indexTx, err := index.BeginTx(ctx, nil)

	if err != nil {
		return 0, fmt.Errorf("begin search rebuild transaction: %w", err)
	}

	defer indexTx.Rollback()

	// Search instances hold a shared lock on this key for their lifetime.
	const searchFence int64 = 759854169704014648
	var locked bool

	if err := indexTx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock($1)`, searchFence).Scan(&locked); err != nil {
		return 0, fmt.Errorf("acquire search rebuild fence: %w", err)
	}

	if !locked {
		return 0, errors.New("search is still running; stop it before rebuilding")
	}

	for _, tx := range []*sql.Tx{userTx, indexTx} {
		var others int

		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid()`).Scan(&others); err != nil {
			return 0, fmt.Errorf("inspect active database sessions: %w", err)
		}

		if others != 0 {
			return 0, errors.New("other database sessions are connected; stop and isolate all clients before rebuilding")
		}
	}

	if _, err := userTx.ExecContext(ctx, `LOCK TABLE users, user_search_events IN ACCESS EXCLUSIVE MODE`); err != nil {
		return 0, fmt.Errorf("lock user search sources: %w", err)
	}

	if _, err := indexTx.ExecContext(ctx, `LOCK TABLE search_documents, search_version_floors IN ACCESS EXCLUSIVE MODE`); err != nil {
		return 0, fmt.Errorf("lock search index: %w", err)
	}

	var highest, floor, current, count int64

	if err := indexTx.QueryRowContext(ctx, `SELECT COALESCE(MAX(source_version),0) FROM search_documents WHERE kind='user'`).Scan(&highest); err != nil {
		return 0, fmt.Errorf("inspect indexed versions: %w", err)
	}

	if err := indexTx.QueryRowContext(ctx, `SELECT min_version FROM search_version_floors WHERE kind='user'`).Scan(&floor); err != nil {
		return 0, fmt.Errorf("inspect user search version floor: %w", err)
	}

	if floor > highest {
		highest = floor
	}

	if err := userTx.QueryRowContext(ctx, `SELECT last_value FROM user_search_events_version_seq`).Scan(&current); err != nil {
		return 0, fmt.Errorf("inspect source sequence: %w", err)
	}

	if err := userTx.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count user profiles: %w", err)
	}

	if current > highest {
		highest = current
	}

	if highest >= math.MaxInt64-count {
		return 0, errors.New("search version space exhausted")
	}

	if _, err := userTx.ExecContext(ctx, `SELECT setval('user_search_events_version_seq', $1, true)`, highest); err != nil {
		return 0, fmt.Errorf("advance search version sequence: %w", err)
	}

	if _, err := userTx.ExecContext(ctx, `DELETE FROM user_search_events`); err != nil {
		return 0, fmt.Errorf("replace pending user search events: %w", err)
	}

	result, err := userTx.ExecContext(ctx, `INSERT INTO user_search_events(user_id,nickname,deleted) SELECT id,nickname,FALSE FROM users`)

	if err != nil {
		return 0, fmt.Errorf("queue user search rebuild: %w", err)
	}

	queued, err := result.RowsAffected()

	if err != nil {
		return 0, fmt.Errorf("count queued search events: %w", err)
	}

	if _, err := indexTx.ExecContext(ctx, `UPDATE search_version_floors SET min_version=$1 WHERE kind='user'`, highest); err != nil {
		return 0, fmt.Errorf("set user search version floor: %w", err)
	}

	if _, err := indexTx.ExecContext(ctx, `DELETE FROM search_documents WHERE kind='user'`); err != nil {
		return 0, fmt.Errorf("clear user search index: %w", err)
	}

	if err := userTx.Commit(); err != nil {
		return 0, fmt.Errorf("commit user search rebuild: %w", err)
	}

	if err := indexTx.Commit(); err != nil {
		return 0, fmt.Errorf("commit search index reset; keep services isolated and retry: %w", err)
	}

	return queued, nil
}
