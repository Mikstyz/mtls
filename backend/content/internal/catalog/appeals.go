package catalog

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type ModerationNotice struct {
	CaseID     uuid.UUID  `json:"case_id"`
	PostID     uuid.UUID  `json:"post_id"`
	CommentID  *uuid.UUID `json:"comment_id,omitempty"`
	Status     string     `json:"status"`
	Rule       *string    `json:"rule,omitempty"`
	Severity   *string    `json:"severity,omitempty"`
	Hidden     bool       `json:"hidden"`
	Appeal     *string    `json:"appeal,omitempty"`
	DecisionAt time.Time  `json:"decision_at"`
}

type PendingAppeal struct {
	CaseID      uuid.UUID  `json:"case_id"`
	PostID      uuid.UUID  `json:"post_id"`
	CommentID   *uuid.UUID `json:"comment_id,omitempty"`
	Statement   string     `json:"statement"`
	SubmittedAt time.Time  `json:"submitted_at"`
}

func (s *Store) ModerationNotices(ctx context.Context, owner uuid.UUID) ([]ModerationNotice, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT case_id,post_id,comment_id,status,rule,severity,hidden,appeal,decision_at FROM public.content_owner_moderation($1)`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	notices := make([]ModerationNotice, 0)
	for rows.Next() {
		var n ModerationNotice
		var comment uuid.NullUUID
		if err := rows.Scan(&n.CaseID, &n.PostID, &comment, &n.Status, &n.Rule, &n.Severity, &n.Hidden, &n.Appeal, &n.DecisionAt); err != nil {
			return nil, err
		}
		if comment.Valid {
			n.CommentID = &comment.UUID
		}

		notices = append(notices, n)
	}
	return notices, rows.Err()
}

func (s *Store) AppealQueue(ctx context.Context, actor uuid.UUID) ([]PendingAppeal, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT case_id,post_id,comment_id,statement,submitted_at FROM public.content_appeal_queue($1)`, actor)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]PendingAppeal, 0)
	for rows.Next() {
		var item PendingAppeal
		var comment uuid.NullUUID
		if err := rows.Scan(&item.CaseID, &item.PostID, &comment, &item.Statement, &item.SubmittedAt); err != nil {
			return nil, err
		}
		if comment.Valid {
			item.CommentID = &comment.UUID
		}

		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) SubmitAppeal(ctx context.Context, owner, caseID uuid.UUID, statement string) (int, error) {
	var status int
	err := s.db.QueryRowContext(ctx, `SELECT public.content_submit_appeal($1,$2,$3)`, owner, caseID, statement).Scan(&status)
	return status, err
}

func (s *Store) ReviewAppeal(ctx context.Context, actor, caseID uuid.UUID, outcome string) (int, error) {
	var status int
	err := s.db.QueryRowContext(ctx, `SELECT public.content_review_appeal($1,$2,$3)`, actor, caseID, outcome).Scan(&status)
	return status, err
}

func (s *Store) AppealDetail(ctx context.Context, actor, id uuid.UUID) (json.RawMessage, error) {
	var body []byte
	if err := s.db.QueryRowContext(ctx, `SELECT public.content_appeal_detail($1,$2)`, actor, id).Scan(&body); err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, ErrPostNotFound
	}

	return json.RawMessage(body), nil
}
