package repositories

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
	"mtls/user/internal/models"
)

var ErrProfileImageUnavailable = errors.New("profile image unavailable")

func (r *userRepo) ProfileImages(ctx context.Context, owner uuid.UUID) (models.ProfileImages, error) {
	const query = `SELECT i.slot,i.media_id FROM user_profile_images i
 JOIN media_permissions p ON p.media_id=i.media_id AND p.owner_id=i.owner_id
 JOIN users u ON u.id=i.owner_id
 WHERE i.owner_id=$1 AND p.ready AND p.revoked_at IS NULL AND p.media_kind='photo'
 AND NOT public.user_profile_image_blocked(i.owner_id,i.media_id)`
	var images models.ProfileImages
	rows, err := r.db.QueryContext(ctx, query, owner)
	if err != nil {
		return images, err
	}
	defer rows.Close()

	for rows.Next() {
		var slot string
		var id uuid.UUID
		if err := rows.Scan(&slot, &id); err != nil {
			return images, err
		}

		switch slot {
		case "avatar":
			images.Avatar = &id
		case "banner":
			images.Banner = &id
		}
	}

	return images, rows.Err()
}

func (r *userRepo) ChangeProfileImage(ctx context.Context, owner uuid.UUID, slot string, media *uuid.UUID) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := lockUserLifecycle(ctx, tx, owner); err != nil {
		return err
	}

	var active bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1)`, owner).Scan(&active); err != nil {
		return err
	}
	if !active {
		return ErrProfileImageUnavailable
	}

	var old uuid.NullUUID
	err = tx.QueryRowContext(ctx, `SELECT media_id FROM user_profile_images WHERE owner_id=$1 AND slot=$2`, owner, slot).Scan(&old)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	if media == nil {
		if !old.Valid {
			return nil
		}

		if _, err := tx.ExecContext(ctx, `DELETE FROM user_profile_images WHERE owner_id=$1 AND slot=$2`, owner, slot); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO user_profile_image_history(owner_id,slot,operation,media_id) VALUES($1,$2,'removed',$3)`, owner, slot, old); err != nil {
			return err
		}

		return tx.Commit()
	}

	var photo uuid.UUID
	err = tx.QueryRowContext(ctx, `SELECT media_id FROM media_permissions WHERE media_id=$1 AND owner_id=$2
 AND ready AND revoked_at IS NULL AND media_kind='photo'
 AND NOT public.user_profile_image_blocked(owner_id,media_id)`, *media, owner).Scan(&photo)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrProfileImageUnavailable
	}
	if err != nil {
		return err
	}
	if old.Valid && old.UUID == photo {
		return nil
	}

	if _, err := tx.ExecContext(ctx, `INSERT INTO user_profile_images(owner_id,slot,media_id) VALUES($1,$2,$3)
 ON CONFLICT(owner_id,slot) DO UPDATE SET media_id=EXCLUDED.media_id`, owner, slot, photo); err != nil {
		return err
	}

	operation := "added"
	if old.Valid {
		operation = "replaced"
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO user_profile_image_history(owner_id,slot,operation,media_id,previous_media_id)
 VALUES($1,$2,$3,$4,$5)`, owner, slot, operation, photo, old); err != nil {
		return err
	}

	return tx.Commit()
}

func (r *userRepo) ProfileImageHistory(ctx context.Context, owner uuid.UUID, before int64) ([]models.ProfileImageChange, error) {
	const query = `SELECT h.id,h.slot,h.operation,h.media_id,h.previous_media_id,h.changed_at,
 COALESCE(p.ready AND p.revoked_at IS NULL AND p.media_kind='photo',FALSE)
 AND NOT public.user_profile_image_blocked(h.owner_id,h.media_id)
 FROM user_profile_image_history h JOIN users u ON u.id=h.owner_id
 LEFT JOIN media_permissions p ON p.media_id=h.media_id AND p.owner_id=h.owner_id
 WHERE h.owner_id=$1 AND ($2::bigint=0 OR h.id<$2) ORDER BY h.id DESC LIMIT 21`

	rows, err := r.db.QueryContext(ctx, query, owner, before)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	changes := make([]models.ProfileImageChange, 0, 21)
	for rows.Next() {
		var item models.ProfileImageChange
		var previous uuid.NullUUID
		if err := rows.Scan(&item.ID, &item.Slot, &item.Operation, &item.MediaID, &previous, &item.ChangedAt, &item.Available); err != nil {
			return nil, err
		}
		if previous.Valid {
			item.Previous = &previous.UUID
		}
		changes = append(changes, item)
	}
	return changes, rows.Err()
}
