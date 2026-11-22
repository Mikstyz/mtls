package catalog

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

func (s *Store) listRecommendations(ctx context.Context, filter Filter) ([]FeedPost, error) {
	var bucket time.Time
	var beforeRank int64
	if filter.Before == nil {
		if err := s.db.QueryRowContext(ctx, `SELECT public.content_ensure_recommendations()`).Scan(&bucket); err != nil {
			return nil, fmt.Errorf("prepare recommendations: %w", err)
		}
	} else {
		position := filter.Before.PublishedAt
		bucket = position.Truncate(time.Hour)
		beforeRank = position.Sub(bucket).Microseconds()
		if beforeRank < 1 || beforeRank > 1000 || filter.Before.ID == uuid.Nil || !position.Equal(bucket.Add(time.Duration(beforeRank)*time.Microsecond)) {
			return nil, ErrInvalidFilter
		}
	}

	var author any
	if filter.Author != nil {
		author = *filter.Author
	}
	const query = `SELECT p.id,p.published_at,p.author_id,p.media_kind,p.title,p.video_duration_ms,` + postCoverMedia + `,` + feedEngagement + `,r.bucket+r.rank*INTERVAL '1 microsecond'
 FROM content_recommendations r JOIN content_posts p ON p.id=r.post_id
 WHERE r.bucket=$1 AND p.status='published' AND p.visibility='public' AND p.hidden_by_case IS NULL
   AND NOT EXISTS (SELECT 1 FROM content_author_purges WHERE author_id=p.author_id)
   AND r.rank>$2
   AND ($3::text='' OR p.media_kind=$3)
   AND ($4::uuid IS NULL OR p.author_id=$4)
   AND ($5::text='' OR (p.media_kind='video' AND CASE $5
      WHEN 'short' THEN p.video_duration_ms<=60000 WHEN 'long' THEN p.video_duration_ms>60000 END))
 ORDER BY r.rank LIMIT $6`

	rows, err := s.db.QueryContext(ctx, query, bucket, beforeRank, filter.Kind, author, filter.Length, filter.Limit, filter.Viewer)
	if err != nil {
		return nil, fmt.Errorf("list recommendations: %w", err)
	}
	defer rows.Close()

	return readFeedPosts(rows, filter.Limit, true)
}
