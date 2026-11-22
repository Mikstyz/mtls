package catalog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

func (s *Store) ViewablePostAuthor(ctx context.Context, viewer, post uuid.UUID) (uuid.UUID, error) {
	const query = `SELECT p.author_id FROM content_posts p
		WHERE p.id = $1 AND p.status = 'published' AND p.hidden_by_case IS NULL
			AND (p.visibility = 'public' OR p.author_id = $2 OR (p.visibility='private' AND $3 AND public.content_test_entitled(p.id,p.revision,$2)))
			AND NOT EXISTS (SELECT 1 FROM content_author_purges a WHERE a.author_id IN (p.author_id, $2))`

	var author uuid.UUID
	err := s.db.QueryRowContext(ctx, query, post, viewer, s.testSales).Scan(&author)

	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, ErrPostNotFound
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("find viewable post author: %w", err)
	}

	return author, nil
}

func (s *Store) SetReaction(ctx context.Context, post, author, viewer uuid.UUID, reaction string, enabled bool) error {
	query := `SELECT public.content_set_reaction($1,$2,$3,$4,$5)`
	if s.testSales {
		query = `SELECT public.content_set_reaction($1,$2,$3,$4,$5,TRUE)`
	}

	var allowed bool
	err := s.db.QueryRowContext(ctx, query, post, author, viewer, reaction, enabled).Scan(&allowed)

	if err != nil {
		return fmt.Errorf("change post reaction: %w", err)
	}
	if !allowed {
		return ErrPostNotFound
	}

	return nil
}
