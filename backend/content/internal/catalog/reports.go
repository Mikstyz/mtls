package catalog

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
)

type Report struct {
	ID        uuid.UUID  `json:"id"`
	PostID    uuid.UUID  `json:"post_id"`
	CommentID *uuid.UUID `json:"comment_id,omitempty"`
	Reason    string     `json:"reason"`
	Status    string     `json:"status"`
	CreatedAt time.Time  `json:"created_at"`
}

func (s *Store) SubmitReport(ctx context.Context, viewer uuid.UUID, report Report) (string, error) {
	var result string
	err := s.db.QueryRowContext(ctx, `SELECT public.content_submit_report($1,$2,$3,$4,$5,$6)`,
		viewer, report.ID, report.PostID, report.CommentID, report.Reason, s.testSales).Scan(&result)
	return result, err
}

func (s *Store) OwnReport(ctx context.Context, viewer, id uuid.UUID) (Report, error) {
	var report Report
	var comment uuid.NullUUID
	err := s.db.QueryRowContext(ctx, `SELECT id,post_id,comment_id,reason,status,created_at FROM public.content_own_report($1,$2)`, viewer, id).
		Scan(&report.ID, &report.PostID, &comment, &report.Reason, &report.Status, &report.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Report{}, ErrPostNotFound
	}
	if comment.Valid {
		report.CommentID = &comment.UUID
	}

	return report, err
}

func (s *Store) ReportCommentAuthor(ctx context.Context, post, comment uuid.UUID) (uuid.UUID, error) {
	var author uuid.UUID
	err := s.db.QueryRowContext(ctx, `SELECT author_id FROM content_comments WHERE id=$1 AND post_id=$2 AND body IS NOT NULL AND hidden_by_case IS NULL`, comment, post).Scan(&author)
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, ErrPostNotFound
	}

	return author, err
}

func (s *Store) SubmitAnonymousSafetyReport(ctx context.Context, target uuid.UUID, reason string) (bool, error) {
	var accepted bool
	err := s.db.QueryRowContext(ctx, `SELECT public.content_submit_anonymous_safety_report($1,$2)`, target, reason).Scan(&accepted)
	return accepted, err
}
