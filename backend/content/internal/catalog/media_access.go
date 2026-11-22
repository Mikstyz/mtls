package catalog

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

func (s *Store) AllowsPostMedia(ctx context.Context, post, media, owner, viewer uuid.UUID, cover bool) (bool, bool, string, error) {
	const query = `WITH visible AS (
		SELECT p.id FROM content_posts p
		WHERE p.id = $1 AND p.author_id = $3 AND p.status = 'published' AND p.hidden_by_case IS NULL
			AND (CASE WHEN $6 THEN $2 = ` + postCoverMedia + `
                ELSE EXISTS (SELECT 1 FROM content_post_media WHERE post_id=p.id AND media_id=$2) END)
			AND (p.visibility = 'public' OR p.author_id = $4 OR (p.visibility='private' AND $5 AND public.content_test_entitled(p.id,p.revision,$4)))
			AND NOT EXISTS (SELECT 1 FROM content_author_purges WHERE author_id = p.author_id)
	)
	SELECT NOT $6 AND public.content_popular_for_playback($1), EXISTS(SELECT 1 FROM visible),
	    COALESCE((SELECT c.frame_name FROM content_video_covers c JOIN visible ON visible.id=c.post_id
	        WHERE $6 AND c.media_id=$2), '')`

	var allowed, popular bool
	var frame string

	if err := s.db.QueryRowContext(ctx, query, post, media, owner, viewer, s.testSales, cover).Scan(&popular, &allowed, &frame); err != nil {
		return false, false, "", fmt.Errorf("check post attachment: %w", err)
	}

	return allowed, allowed && popular, frame, nil
}

func (s *Store) RevokeMediaAttachment(ctx context.Context, owner, media uuid.UUID) (bool, error) {
	var accepted bool
	err := s.db.QueryRowContext(ctx, `SELECT public.content_revoke_media_attachment($1,$2)`, owner, media).Scan(&accepted)
	return accepted, err
}
