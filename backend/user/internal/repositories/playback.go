package repositories

import (
	"context"

	"github.com/google/uuid"
	"mtls/user/internal/models"
)

func (r *userRepo) PlaybackSettings(ctx context.Context, id uuid.UUID) (models.PlaybackSettings, error) {
	var s models.PlaybackSettings
	err := r.db.QueryRowContext(ctx, "SELECT photo_quality,video_quality FROM users WHERE id=$1", id).Scan(&s.Photo, &s.Video)
	return s, err
}

func (r *userRepo) SetPlaybackSettings(ctx context.Context, id uuid.UUID, s models.PlaybackSettings) error {
	var updated uuid.UUID
	return r.db.QueryRowContext(ctx, "UPDATE users SET photo_quality=$2,video_quality=$3 WHERE id=$1 RETURNING id", id, s.Photo, s.Video).Scan(&updated)
}
