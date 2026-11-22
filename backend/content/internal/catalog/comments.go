package catalog

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

type Comment struct {
	ID        uuid.UUID `json:"id"`
	AuthorID  uuid.UUID `json:"author_id"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Store) WriteComment(ctx context.Context, post, viewer, id uuid.UUID, body *string) (int, error) {
	var status int
	query := `SELECT public.content_write_comment($1,$2,$3,$4)`
	if s.testSales {
		query = `SELECT public.content_write_comment($1,$2,$3,$4,TRUE)`
	}
	err := s.db.QueryRowContext(ctx, query, post, viewer, id, body).Scan(&status)
	if err != nil {
		return 0, err
	}

	switch status {
	case 201, 204, 403, 404, 409, 429:
		return status, nil
	default:
		return 0, errors.New("unknown comment operation result")
	}
}

func (s *Store) ListComments(ctx context.Context, post, viewer uuid.UUID, limit int, before *time.Time, id uuid.UUID) ([]Comment, error) {
	if limit < 1 || limit > 41 {
		return nil, ErrInvalidFilter
	}
	const query = `SELECT c.id,c.author_id,c.body,c.created_at FROM content_comments c
 JOIN content_posts p ON p.id=c.post_id
 WHERE p.id=$1 AND p.status='published' AND p.hidden_by_case IS NULL AND (p.visibility='public' OR p.author_id=$2 OR (p.visibility='private' AND $6 AND public.content_test_entitled(p.id,p.revision,$2)))
 AND c.body IS NOT NULL AND c.hidden_by_case IS NULL AND NOT EXISTS (
 SELECT 1 FROM content_author_purges WHERE author_id IN (c.author_id,p.author_id,$2))
 AND ($3::timestamptz IS NULL OR (c.created_at,c.id)<($3,$4))
 ORDER BY c.created_at DESC,c.id DESC LIMIT $5`

	rows, err := s.db.QueryContext(ctx, query, post, viewer, before, id, limit, s.testSales)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]Comment, 0, limit)
	for rows.Next() {
		var item Comment
		if err := rows.Scan(&item.ID, &item.AuthorID, &item.Body, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
