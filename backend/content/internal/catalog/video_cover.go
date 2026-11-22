package catalog

import (
	"context"

	"github.com/google/uuid"
)

const primaryPostMedia = `(SELECT m.media_id FROM content_post_media m WHERE m.post_id=p.id ORDER BY m.position LIMIT 1)`

const postCoverMedia = `COALESCE(
 (SELECT c.media_id FROM content_video_covers c WHERE c.post_id=p.id
     AND (c.frame_name IS NULL OR c.media_id=` + primaryPostMedia + `)),
 ` + primaryPostMedia + `
)`

func (s *Store) SetVideoCover(ctx context.Context, owner, id uuid.UUID, revision int64, photo *uuid.UUID, frame *string) error {
	var result int64
	err := s.db.QueryRowContext(ctx, `SELECT public.content_set_video_cover($1,$2,$3,$4,$5)`, owner, id, revision, photo, frame).Scan(&result)
	if err != nil {
		return err
	}

	switch result {
	case -1:
		return ErrPostNotFound
	case 0:
		return ErrDraftVersionConflict
	default:
		return nil
	}
}
