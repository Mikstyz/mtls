package catalog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

const purgeBatchSize = 500

var (
	ErrMediaCleanupPending = errors.New("media cleanup is not available")
	ErrCleanupInProgress   = errors.New("author content cleanup is in progress")
)

// PurgeAuthor removes a bounded batch and retains its marker until cleanup finishes.
func (s *Store) PurgeAuthor(ctx context.Context, author uuid.UUID) error {
	if author == uuid.Nil {
		return errors.New("invalid author")
	}

	tx, err := s.db.BeginTx(ctx, nil)

	if err != nil {
		return fmt.Errorf("begin author content purge: %w", err)
	}

	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "content-author:"+author.String()); err != nil {
		return fmt.Errorf("lock content author: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `INSERT INTO content_author_purges(author_id) VALUES($1) ON CONFLICT(author_id) DO NOTHING`, author); err != nil {
		return fmt.Errorf("record author content purge: %w", err)
	}

	var reactionsRemoved bool
	if err := tx.QueryRowContext(ctx, `SELECT public.content_purge_viewer_reactions($1)`, author).Scan(&reactionsRemoved); err != nil {
		return fmt.Errorf("purge viewer reactions: %w", err)
	}
	if !reactionsRemoved {
		if err := tx.QueryRowContext(ctx, `SELECT public.content_purge_view_receipts($1)`, author).Scan(&reactionsRemoved); err != nil {
			return fmt.Errorf("purge viewer receipts: %w", err)
		}
	}
	if reactionsRemoved {
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit viewer reaction purge: %w", err)
		}
		return ErrCleanupInProgress
	}

	ids, err := lockPurgeBatch(ctx, tx, author)

	if err != nil {
		return err
	}

	if err := removePurgeBatch(ctx, tx, author, ids); err != nil {
		if !errors.Is(err, ErrMediaCleanupPending) {
			return err
		}

		// Keep the author marker while files still require separate cleanup.
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit pending media cleanup: %w", err)
		}

		return ErrMediaCleanupPending
	}

	var remaining bool

	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM content_posts WHERE author_id=$1)`, author).Scan(&remaining); err != nil {
		return fmt.Errorf("check remaining author posts: %w", err)
	}

	if !remaining {
		if _, err := tx.ExecContext(ctx, `DELETE FROM content_author_purges WHERE author_id=$1`, author); err != nil {
			return fmt.Errorf("finish author content purge: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit author content purge: %w", err)
	}

	if remaining {
		return ErrCleanupInProgress
	}

	return nil
}

func lockPurgeBatch(ctx context.Context, tx *sql.Tx, author uuid.UUID) ([]string, error) {
	const query = `SELECT id FROM content_posts
		WHERE author_id = $1 ORDER BY id LIMIT $2 FOR UPDATE`

	rows, err := tx.QueryContext(ctx, query, author, purgeBatchSize)

	if err != nil {
		return nil, fmt.Errorf("lock author posts: %w", err)
	}

	defer rows.Close()
	ids := make([]string, 0, purgeBatchSize)

	for rows.Next() {
		var id uuid.UUID

		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("read author posts: %w", err)
		}

		ids = append(ids, id.String())
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read author posts: %w", err)
	}

	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close author posts: %w", err)
	}

	return ids, nil
}

func removePurgeBatch(ctx context.Context, tx *sql.Tx, author uuid.UUID, ids []string) error {
	if len(ids) == 0 {
		return nil
	}

	var hasMedia bool

	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM content_post_media WHERE post_id = ANY($1::uuid[]))`, pq.Array(ids)).Scan(&hasMedia); err != nil {
		return fmt.Errorf("check author media: %w", err)
	}

	if hasMedia {
		return ErrMediaCleanupPending
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM content_draft_requests WHERE author_id = $1 AND post_id = ANY($2::uuid[])`, author, pq.Array(ids)); err != nil {
		return fmt.Errorf("purge draft requests: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM content_posts WHERE author_id = $1 AND id = ANY($2::uuid[])`, author, pq.Array(ids)); err != nil {
		return fmt.Errorf("purge author posts: %w", err)
	}

	return nil
}
