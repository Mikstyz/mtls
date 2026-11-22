package catalog

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type OwnerPost struct {
	ID           uuid.UUID  `json:"id"`
	Kind         string     `json:"kind"`
	Title        string     `json:"title"`
	Status       string     `json:"status"`
	State        string     `json:"state"`
	Visibility   string     `json:"visibility"`
	Revision     int64      `json:"revision"`
	CreatedAt    time.Time  `json:"created_at"`
	PublishedAt  *time.Time `json:"published_at,omitempty"`
	PublishAt    *time.Time `json:"publish_at,omitempty"`
	CoverMediaID *uuid.UUID `json:"cover_media_id,omitempty"`
}

func ValidLibraryState(state string) bool {
	switch state {
	case "", "draft", "scheduled", "published", "removed", "hidden":
		return true
	default:
		return false
	}
}

func (s *Store) OwnerLibrary(ctx context.Context, owner uuid.UUID, state string, limit int, before *DraftCursor) ([]OwnerPost, error) {
	if owner == uuid.Nil || limit < 1 || limit > 41 || !ValidLibraryState(state) ||
		before != nil && (before.ID == uuid.Nil || before.CreatedAt.IsZero()) {
		return nil, ErrInvalidFilter
	}

	var beforeTime, beforeID any
	if before != nil {
		beforeTime, beforeID = before.CreatedAt, before.ID
	}

	const query = `SELECT p.id,p.media_kind,p.title,p.status,derived.state,p.visibility,p.revision,
 p.created_at,p.published_at,s.publish_at,` + postCoverMedia + `
 FROM content_posts p LEFT JOIN content_scheduled_posts s ON s.post_id=p.id AND s.revision=p.revision AND p.status='draft'
 CROSS JOIN LATERAL (SELECT CASE WHEN p.hidden_by_case IS NOT NULL THEN 'hidden'
     WHEN s.schedule_id IS NOT NULL THEN 'scheduled' ELSE p.status END AS state) derived
 WHERE p.author_id=$1 AND NOT EXISTS (SELECT 1 FROM content_author_purges WHERE author_id=$1)
     AND ($2::text='' OR derived.state=$2)
     AND ($3::timestamptz IS NULL OR (p.created_at,p.id)<($3,$4::uuid))
 ORDER BY p.created_at DESC,p.id DESC LIMIT $5`

	rows, err := s.db.QueryContext(ctx, query, owner, state, beforeTime, beforeID, limit)
	if err != nil {
		return nil, fmt.Errorf("list owner posts: %w", err)
	}
	defer rows.Close()

	items := make([]OwnerPost, 0, limit)
	for rows.Next() {
		var item OwnerPost
		var cover uuid.NullUUID
		if err := rows.Scan(&item.ID, &item.Kind, &item.Title, &item.Status, &item.State, &item.Visibility, &item.Revision,
			&item.CreatedAt, &item.PublishedAt, &item.PublishAt, &cover); err != nil {
			return nil, fmt.Errorf("read owner post: %w", err)
		}
		if cover.Valid {
			item.CoverMediaID = &cover.UUID
		}

		items = append(items, item)
	}
	return items, rows.Err()
}
