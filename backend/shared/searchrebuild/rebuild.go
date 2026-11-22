package searchrebuild

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
)

type sourceQueries struct {
	lock, sequence, count, advance, clear, enqueue string
}

func queries(kind string) (sourceQueries, error) {
	switch kind {
	case "user":
		return sourceQueries{
			lock:     "LOCK TABLE users, user_search_events IN ACCESS EXCLUSIVE MODE",
			sequence: "SELECT last_value FROM user_search_events_version_seq",
			count:    "SELECT count(*) FROM users",
			advance:  "SELECT setval('user_search_events_version_seq', $1, true)",
			clear:    "DELETE FROM user_search_events",
			enqueue:  "INSERT INTO user_search_events(user_id,nickname,deleted) SELECT id,nickname,FALSE FROM users",
		}, nil
	case "content":
		const eligible = ` FROM content_posts p WHERE status='published' AND visibility='public' AND hidden_by_case IS NULL
       AND NOT EXISTS (SELECT 1 FROM content_author_purges a WHERE a.author_id=p.author_id)`
		return sourceQueries{
			lock:     "LOCK TABLE content_posts, content_author_purges, content_search_events IN ACCESS EXCLUSIVE MODE",
			sequence: "SELECT last_value FROM content_search_events_version_seq",
			count:    "SELECT count(*)" + eligible,
			advance:  "SELECT setval('content_search_events_version_seq', $1, true)",
			clear:    "DELETE FROM content_search_events",
			enqueue:  "INSERT INTO content_search_events(post_id,title,deleted) SELECT id,title,FALSE" + eligible,
		}, nil
	default:
		return sourceQueries{}, errors.New("unknown search source")
	}
}

// RebuildOffline replaces one source index through the outbox. All source publishers
// and search writers must be stopped and isolated until the operation succeeds.
func RebuildOffline(ctx context.Context, source, index *sql.DB, kind string) (int64, error) {
	if source == nil || index == nil {
		return 0, errors.New("both databases are required")
	}

	q, err := queries(kind)
	if err != nil {
		return 0, err
	}

	sourceTx, err := source.BeginTx(ctx, nil)

	if err != nil {
		return 0, fmt.Errorf("begin source rebuild transaction: %w", err)
	}

	defer sourceTx.Rollback()

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

	for _, tx := range []*sql.Tx{sourceTx, indexTx} {
		if _, err := tx.ExecContext(ctx, "SET LOCAL row_security=off"); err != nil {
			return 0, err
		}

		var others int

		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid()`).Scan(&others); err != nil {
			return 0, fmt.Errorf("inspect active database sessions: %w", err)
		}

		if others != 0 {
			return 0, errors.New("other database sessions are connected; stop and isolate all clients before rebuilding")
		}
	}

	if _, err := sourceTx.ExecContext(ctx, q.lock); err != nil {
		return 0, fmt.Errorf("lock source search sources: %w", err)
	}

	if _, err := indexTx.ExecContext(ctx, `LOCK TABLE search_documents, search_version_floors IN ACCESS EXCLUSIVE MODE`); err != nil {
		return 0, fmt.Errorf("lock search index: %w", err)
	}

	var highest, floor, current, count int64

	if err := indexTx.QueryRowContext(ctx, `SELECT COALESCE(MAX(source_version),0) FROM search_documents WHERE kind=$1`, kind).Scan(&highest); err != nil {
		return 0, fmt.Errorf("inspect indexed versions: %w", err)
	}

	if err := indexTx.QueryRowContext(ctx, `SELECT min_version FROM search_version_floors WHERE kind=$1`, kind).Scan(&floor); err != nil {
		return 0, fmt.Errorf("inspect source search version floor: %w", err)
	}

	if floor > highest {
		highest = floor
	}

	if err := sourceTx.QueryRowContext(ctx, q.sequence).Scan(&current); err != nil {
		return 0, fmt.Errorf("inspect source sequence: %w", err)
	}

	if err := sourceTx.QueryRowContext(ctx, q.count).Scan(&count); err != nil {
		return 0, fmt.Errorf("count source records: %w", err)
	}

	if current > highest {
		highest = current
	}

	if highest >= math.MaxInt64-count {
		return 0, errors.New("search version space exhausted")
	}

	if _, err := sourceTx.ExecContext(ctx, q.advance, highest); err != nil {
		return 0, fmt.Errorf("advance search version sequence: %w", err)
	}

	if _, err := sourceTx.ExecContext(ctx, q.clear); err != nil {
		return 0, fmt.Errorf("replace pending source search events: %w", err)
	}

	result, err := sourceTx.ExecContext(ctx, q.enqueue)

	if err != nil {
		return 0, fmt.Errorf("queue source search rebuild: %w", err)
	}

	queued, err := result.RowsAffected()

	if err != nil {
		return 0, fmt.Errorf("count queued search events: %w", err)
	}

	if _, err := indexTx.ExecContext(ctx, `UPDATE search_version_floors SET min_version=$2 WHERE kind=$1`, kind, highest); err != nil {
		return 0, fmt.Errorf("set source search version floor: %w", err)
	}

	if _, err := indexTx.ExecContext(ctx, `DELETE FROM search_documents WHERE kind=$1`, kind); err != nil {
		return 0, fmt.Errorf("clear source search index: %w", err)
	}

	if err := sourceTx.Commit(); err != nil {
		return 0, fmt.Errorf("commit source search rebuild: %w", err)
	}

	if err := indexTx.Commit(); err != nil {
		return 0, fmt.Errorf("commit search index reset; keep services isolated and retry: %w", err)
	}

	return queued, nil
}
