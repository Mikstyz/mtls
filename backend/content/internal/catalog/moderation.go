package catalog

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type ModerationCase struct {
	ID        uuid.UUID  `json:"case_id"`
	PostID    uuid.UUID  `json:"post_id"`
	CommentID *uuid.UUID `json:"comment_id,omitempty"`
	Reason    string     `json:"reason"`
	Status    string     `json:"status"`
	Revision  int64      `json:"revision"`
	Escalated bool       `json:"escalated"`
	CreatedAt time.Time  `json:"created_at"`
}

type ModerationAction struct {
	Request  uuid.UUID `json:"request_id"`
	Revision int64     `json:"revision"`
	Action   string    `json:"action"`
	Rule     *string   `json:"rule,omitempty"`
	Severity *string   `json:"severity,omitempty"`
}

type ModerationQueueCursor struct {
	Escalated bool      `json:"escalated"`
	CreatedAt time.Time `json:"created_at"`
	CaseID    uuid.UUID `json:"case_id"`
}

func (s *Store) ModerationQueue(ctx context.Context, actor uuid.UUID, after *ModerationQueueCursor) ([]ModerationCase, error) {
	var escalated, createdAt, caseID any
	if after != nil {
		escalated, createdAt, caseID = after.Escalated, after.CreatedAt, after.CaseID
	}

	const query = `SELECT * FROM public.content_moderation_queue($1,$2,$3,$4)`
	rows, err := s.db.QueryContext(ctx, query, actor, escalated, createdAt, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]ModerationCase, 0)
	for rows.Next() {
		var item ModerationCase
		var comment uuid.NullUUID
		if err := rows.Scan(&item.ID, &item.PostID, &comment, &item.Reason, &item.Status, &item.Revision, &item.Escalated, &item.CreatedAt); err != nil {
			return nil, err
		}
		if comment.Valid {
			item.CommentID = &comment.UUID
		}

		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) ModerateReport(ctx context.Context, actor, target uuid.UUID, action ModerationAction) (int64, error) {
	var next int64
	err := s.db.QueryRowContext(ctx, `SELECT public.content_moderate_report($1,$2,$3,$4,$5,$6,$7)`,
		actor, target, action.Request, action.Revision, action.Action, action.Rule, action.Severity).Scan(&next)
	if err != nil {
		return 0, err
	}

	switch next {
	case -1:
		return 0, ErrPostNotFound
	case 0:
		return 0, ErrDraftVersionConflict
	default:
		return next, nil
	}
}

func (s *Store) ModerationCaseDetail(ctx context.Context, actor, target uuid.UUID, before *int64) (json.RawMessage, error) {
	var body []byte
	const query = `SELECT public.content_moderation_case_detail($1,$2,$3)`
	if err := s.db.QueryRowContext(ctx, query, actor, target, before).Scan(&body); err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, ErrPostNotFound
	}
	return json.RawMessage(body), nil
}

func (s *Store) AllowsCaseMedia(ctx context.Context, actor, target, asset, owner uuid.UUID) (bool, error) {
	var allowed bool
	err := s.db.QueryRowContext(ctx, `SELECT public.content_case_media_access($1,$2,$3,$4)`,
		actor, target, asset, owner).Scan(&allowed)
	return allowed, err
}
