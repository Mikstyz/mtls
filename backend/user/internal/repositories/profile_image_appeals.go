package repositories

import (
	"context"

	"github.com/google/uuid"
	"mtls/user/internal/models"
)

func (r *userRepo) ProfileImageNotices(ctx context.Context, owner uuid.UUID) ([]models.ProfileImageNotice, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT * FROM public.user_profile_image_notices($1)`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]models.ProfileImageNotice, 0)
	for rows.Next() {
		var item models.ProfileImageNotice
		if err := rows.Scan(&item.CaseID, &item.Slot, &item.MediaID, &item.Reason, &item.DecidedAt, &item.Appeal); err != nil {
			return nil, err
		}
		items = append(items, item)
	}

	return items, rows.Err()
}

func (r *userRepo) ProfileImageAppeals(ctx context.Context, actor uuid.UUID) ([]models.ProfileImageAppeal, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT * FROM public.user_profile_image_appeal_queue($1)`, actor)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]models.ProfileImageAppeal, 0)
	for rows.Next() {
		var item models.ProfileImageAppeal
		if err := rows.Scan(&item.CaseID, &item.OwnerID, &item.Slot, &item.MediaID, &item.Reason, &item.Statement, &item.SubmittedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}

	return items, rows.Err()
}

func (r *userRepo) SubmitProfileImageAppeal(ctx context.Context, owner, id uuid.UUID, statement string) (int, error) {
	var result int
	err := r.db.QueryRowContext(ctx, `SELECT public.user_submit_profile_image_appeal($1,$2,$3)`, owner, id, statement).Scan(&result)
	return result, err
}

func (r *userRepo) ReviewProfileImageAppeal(ctx context.Context, actor, id uuid.UUID, outcome string) (int, error) {
	var result int
	err := r.db.QueryRowContext(ctx, `SELECT public.user_review_profile_image_appeal($1,$2,$3)`, actor, id, outcome).Scan(&result)
	return result, err
}
