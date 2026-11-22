package catalog

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

type ScheduledPost struct {
	ID       uuid.UUID
	PostID   uuid.UUID
	AuthorID uuid.UUID
	Kind     string
	MediaIDs []string
}

func (s *Store) SchedulePost(ctx context.Context, owner, id uuid.UUID, revision int64, at *time.Time, visibility string) (int, error) {
	var status int
	err := s.db.QueryRowContext(ctx, `SELECT public.content_schedule_post($1,$2,$3,$4,$5)`, owner, id, revision, at, visibility).Scan(&status)
	return status, err
}

func (s *Store) ClaimScheduledPost(ctx context.Context) (*ScheduledPost, error) {
	var job ScheduledPost
	err := s.db.QueryRowContext(ctx, `SELECT schedule_id,post_id,author_id,media_kind,media_ids FROM public.content_claim_scheduled_post()`).
		Scan(&job.ID, &job.PostID, &job.AuthorID, &job.Kind, pq.Array(&job.MediaIDs))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &job, err
}

func (s *Store) PublishScheduledPost(ctx context.Context, job ScheduledPost, duration *int64) error {
	var published bool
	return s.db.QueryRowContext(ctx, `SELECT public.content_publish_scheduled_post($1,$2,$3,$4)`, job.PostID, job.ID, job.AuthorID, duration).Scan(&published)
}
