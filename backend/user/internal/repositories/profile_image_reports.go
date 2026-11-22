package repositories

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"mtls/user/internal/models"
)

func (r *userRepo) ReportProfileImage(ctx context.Context, actor, request uuid.UUID, report models.ProfileImageReport) (int, error) {
	var result int
	const query = `SELECT public.user_report_profile_image($1,$2,$3,$4,$5,$6)`
	if err := r.db.QueryRowContext(ctx, query, actor, request, report.OwnerID, report.Slot, report.MediaID, report.Reason).Scan(&result); err != nil {
		return 0, fmt.Errorf("record profile image report: %w", err)
	}

	return result, nil
}

func (r *userRepo) OwnProfileImageReport(ctx context.Context, actor, request uuid.UUID) (models.ProfileImageReport, error) {
	var report models.ProfileImageReport
	const query = `SELECT owner_id,slot,media_id,reason,status,created_at FROM public.user_own_profile_image_report($1,$2)`
	if err := r.db.QueryRowContext(ctx, query, actor, request).Scan(
		&report.OwnerID, &report.Slot, &report.MediaID, &report.Reason, &report.Status, &report.CreatedAt,
	); err != nil {
		return models.ProfileImageReport{}, fmt.Errorf("read profile image report: %w", err)
	}

	return report, nil
}

func (r *userRepo) ProfileImageModerationQueue(ctx context.Context, actor uuid.UUID) ([]models.ProfileImageCase, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT case_id,owner_id,slot,media_id,reason,created_at FROM public.user_profile_image_moderation_queue($1)`, actor)
	if err != nil {
		return nil, fmt.Errorf("load profile moderation queue: %w", err)
	}
	defer rows.Close()

	cases := make([]models.ProfileImageCase, 0)
	for rows.Next() {
		var item models.ProfileImageCase
		if err := rows.Scan(&item.CaseID, &item.OwnerID, &item.Slot, &item.MediaID, &item.Reason, &item.CreatedAt); err != nil {
			return nil, err
		}
		cases = append(cases, item)
	}

	return cases, rows.Err()
}

func (r *userRepo) DecideProfileImageReport(ctx context.Context, actor, target, request uuid.UUID, decision string) (int, error) {
	var result int
	const query = `SELECT public.user_decide_profile_image_report($1,$2,$3,$4)`
	if err := r.db.QueryRowContext(ctx, query, actor, target, request, decision).Scan(&result); err != nil {
		return 0, fmt.Errorf("decide profile image report: %w", err)
	}

	return result, nil
}

func (r *userRepo) ProfileModerationMediaOwner(ctx context.Context, actor, target, media uuid.UUID) (uuid.UUID, error) {
	var owner uuid.NullUUID
	const query = `SELECT public.user_profile_moderation_media_owner($1,$2,$3)`
	if err := r.db.QueryRowContext(ctx, query, actor, target, media).Scan(&owner); err != nil {
		return uuid.Nil, fmt.Errorf("check profile moderation image: %w", err)
	}

	return owner.UUID, nil
}
