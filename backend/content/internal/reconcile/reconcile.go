package reconcile

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

func lockAuthSchema(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `LOCK TABLE content_reconciliation_authors IN ACCESS SHARE MODE NOWAIT`); err != nil {
		return fmt.Errorf("lock auth schema: %w", err)
	}

	var locked bool

	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (
		SELECT 1 FROM pg_locks
		WHERE pid = pg_backend_pid() AND relation = 'credentials'::regclass
			AND mode = 'AccessShareLock' AND granted
	)`).Scan(&locked); err != nil {
		return fmt.Errorf("verify auth schema lock: %w", err)
	}

	if !locked {
		return errors.New("reconciliation view did not lock credentials")
	}

	return nil
}

// Offline compares content against a verified, authoritative auth snapshot.
// All writers must be stopped and isolated for the entire operation.
func Offline(ctx context.Context, auth, content *sql.DB, apply bool) (int64, error) {
	if auth == nil || content == nil {
		return 0, errors.New("both databases are required")
	}

	authTx, err := auth.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})

	if err != nil {
		return 0, fmt.Errorf("begin auth snapshot: %w", err)
	}

	defer authTx.Rollback()

	if err := lockAuthSchema(ctx, authTx); err != nil {
		return 0, err
	}

	contentTx, err := content.BeginTx(ctx, nil)

	if err != nil {
		return 0, fmt.Errorf("begin content reconciliation: %w", err)
	}

	defer contentTx.Rollback()

	if _, err := contentTx.ExecContext(ctx, `LOCK TABLE content_posts, content_post_media,
		content_draft_requests, content_author_purges, content_post_likes, content_post_favorites,
		content_post_statistics, content_post_view_receipts, content_comments, content_test_orders, content_test_offers, content_ad_deliveries, content_reports, content_moderation_events, content_moderation_appeals, content_points_accounts, content_points_ledger, content_points_warnings, content_points_bans, content_scheduled_posts IN ACCESS EXCLUSIVE MODE NOWAIT`); err != nil {
		return 0, fmt.Errorf("lock content data: %w", err)
	}

	for _, tx := range []*sql.Tx{authTx, contentTx} {
		var others int

		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid()`).Scan(&others); err != nil {
			return 0, fmt.Errorf("inspect database sessions: %w", err)
		}

		if others != 0 {
			return 0, errors.New("other database sessions are connected; isolate all clients")
		}
	}

	var authRLS bool

	if err := authTx.QueryRowContext(ctx, `SELECT relrowsecurity OR relforcerowsecurity FROM pg_class WHERE oid='credentials'::regclass`).Scan(&authRLS); err != nil {
		return 0, fmt.Errorf("inspect auth row security: %w", err)
	}

	if authRLS {
		return 0, errors.New("auth row security prevents a complete reconciliation")
	}

	var contentRLS bool

	if err := contentTx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_class
		WHERE oid = ANY(ARRAY['content_posts'::regclass, 'content_post_media'::regclass,
			'content_draft_requests'::regclass, 'content_author_purges'::regclass, 'content_post_likes'::regclass,
			'content_post_favorites'::regclass, 'content_post_statistics'::regclass, 'content_post_view_receipts'::regclass, 'content_comments'::regclass, 'content_test_orders'::regclass, 'content_test_offers'::regclass, 'content_ad_deliveries'::regclass, 'content_reports'::regclass, 'content_moderation_events'::regclass, 'content_moderation_appeals'::regclass, 'content_points_accounts'::regclass, 'content_points_ledger'::regclass, 'content_points_warnings'::regclass, 'content_points_bans'::regclass, 'content_scheduled_posts'::regclass])
		AND (relrowsecurity OR relforcerowsecurity))`).Scan(&contentRLS); err != nil {
		return 0, fmt.Errorf("inspect content row security: %w", err)
	}

	if contentRLS {
		return 0, errors.New("content row security prevents a complete reconciliation")
	}

	var accounts int64

	if err := authTx.QueryRowContext(ctx, `SELECT count(*) FROM credentials`).Scan(&accounts); err != nil {
		return 0, fmt.Errorf("inspect auth source: %w", err)
	}

	if accounts == 0 {
		return 0, errors.New("auth source has no accounts; refusing to infer deletions")
	}

	var cursor any
	var total int64

	for {
		const query = `SELECT account_id FROM (
			SELECT author_id AS account_id FROM content_posts
			UNION SELECT author_id FROM content_author_purges
			UNION SELECT viewer_id FROM content_post_likes
			UNION SELECT viewer_id FROM content_post_favorites
			UNION SELECT viewer_id FROM content_post_view_receipts
            UNION SELECT author_id FROM content_comments
            UNION SELECT buyer_id FROM content_test_orders
            UNION SELECT viewer_id FROM content_ad_deliveries
            UNION SELECT reporter_id FROM content_reports WHERE reporter_id IS NOT NULL
            UNION SELECT owner_id FROM content_points_accounts
		) AS accounts WHERE ($1::uuid IS NULL OR account_id > $1::uuid)
		ORDER BY account_id LIMIT 500`
		rows, err := contentTx.QueryContext(ctx, query, cursor)

		if err != nil {
			return 0, fmt.Errorf("list content authors: %w", err)
		}

		ids := make([]uuid.UUID, 0, 500)
		values := make([]string, 0, 500)

		for rows.Next() {
			var id uuid.UUID

			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return 0, fmt.Errorf("read content author: %w", err)
			}

			if id == uuid.Nil {
				rows.Close()
				return 0, errors.New("invalid content author")
			}

			ids = append(ids, id)
			values = append(values, id.String())
		}

		if err := rows.Err(); err != nil {
			rows.Close()
			return 0, fmt.Errorf("read content authors: %w", err)
		}

		if err := rows.Close(); err != nil {
			return 0, fmt.Errorf("close content authors: %w", err)
		}

		if len(ids) == 0 {
			break
		}

		found := make(map[uuid.UUID]bool, len(ids))
		authRows, err := authTx.QueryContext(ctx, `SELECT user_id FROM credentials WHERE user_id=ANY($1::uuid[])`, pq.Array(values))

		if err != nil {
			return 0, fmt.Errorf("check author accounts: %w", err)
		}

		for authRows.Next() {
			var id uuid.UUID

			if err := authRows.Scan(&id); err != nil {
				authRows.Close()
				return 0, fmt.Errorf("read author account: %w", err)
			}

			found[id] = true
		}

		if err := authRows.Err(); err != nil {
			authRows.Close()
			return 0, fmt.Errorf("read author accounts: %w", err)
		}

		if err := authRows.Close(); err != nil {
			return 0, fmt.Errorf("close author accounts: %w", err)
		}

		for _, id := range ids {
			if found[id] {
				continue
			}

			var media bool

			if err := contentTx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM content_post_media m JOIN content_posts p ON p.id=m.post_id WHERE p.author_id=$1)`, id).Scan(&media); err != nil {
				return 0, fmt.Errorf("check author media: %w", err)
			}

			if media {
				return 0, errors.New("unresolved media cleanup; content remains isolated")
			}

			total++

			if !apply {
				continue
			}

			if err := removeViewerReactions(ctx, contentTx, id); err != nil {
				return 0, err
			}

			if _, err := contentTx.ExecContext(ctx, `DELETE FROM content_draft_requests WHERE author_id=$1`, id); err != nil {
				return 0, fmt.Errorf("remove author draft requests: %w", err)
			}

			if _, err := contentTx.ExecContext(ctx, `DELETE FROM content_posts WHERE author_id=$1`, id); err != nil {
				return 0, fmt.Errorf("remove author posts: %w", err)
			}
			if _, err := contentTx.ExecContext(ctx, `DELETE FROM content_author_purges WHERE author_id=$1`, id); err != nil {
				return 0, fmt.Errorf("remove author cleanup marker: %w", err)
			}
		}

		cursor = ids[len(ids)-1].String()
	}

	if !apply {
		return total, nil
	}

	if err := contentTx.Commit(); err != nil {
		return 0, fmt.Errorf("commit content reconciliation: %w", err)
	}

	return total, nil
}

func removeViewerReactions(ctx context.Context, tx *sql.Tx, id uuid.UUID) error {
	const removeLikes = `WITH removed AS (
		DELETE FROM content_post_likes WHERE viewer_id = $1 RETURNING post_id
	), updated AS (
		UPDATE content_post_statistics s SET likes = s.likes - 1
		FROM removed r WHERE s.post_id = r.post_id RETURNING s.post_id
	)
	SELECT (SELECT count(*) FROM removed) = (SELECT count(*) FROM updated)`
	var consistent bool

	if err := tx.QueryRowContext(ctx, removeLikes, id).Scan(&consistent); err != nil {
		return fmt.Errorf("remove viewer likes: %w", err)
	}
	if !consistent {
		return errors.New("missing post statistics during content reconciliation")
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM content_post_favorites WHERE viewer_id = $1`, id); err != nil {
		return fmt.Errorf("remove viewer favorites: %w", err)
	}
	for {
		var changed bool
		if err := tx.QueryRowContext(ctx, `SELECT public.content_erase_reporter($1)`, id).Scan(&changed); err != nil {
			return fmt.Errorf("erase reporter identity: %w", err)
		}
		if !changed {
			break
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM content_points_accounts WHERE owner_id=$1`, id); err != nil {
		return fmt.Errorf("remove moderation points: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM content_ad_deliveries WHERE viewer_id=$1`, id); err != nil {
		return fmt.Errorf("remove ad deliveries: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM content_test_orders WHERE buyer_id=$1`, id); err != nil {
		return fmt.Errorf("remove test orders: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM content_comments WHERE author_id=$1`, id); err != nil {
		return fmt.Errorf("remove author comments: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM content_post_view_receipts WHERE viewer_id = $1`, id); err != nil {
		return fmt.Errorf("remove viewer receipts: %w", err)
	}

	return nil
}
