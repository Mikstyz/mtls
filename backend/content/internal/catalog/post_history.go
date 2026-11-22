package catalog

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
)

const PostHistoryPageSize = 20

type PostHistoryItem struct {
	EventID    int64     `json:"event_id"`
	Revision   int64     `json:"revision"`
	State      string    `json:"state"`
	Visibility string    `json:"visibility"`
	Operation  string    `json:"operation"`
	ChangedAt  time.Time `json:"changed_at"`
}

func (s *Store) PostHistory(ctx context.Context, author, id uuid.UUID, beforeRevision, beforeEvent int64) ([]PostHistoryItem, error) {
	const query = `SELECT h.event_id,h.revision,h.state,h.visibility,h.operation,h.changed_at
        FROM content_posts p LEFT JOIN LATERAL (
            SELECT event_id,revision,state,visibility,operation,changed_at FROM content_post_history
            WHERE post_id=p.id AND ($3::bigint=0 OR (revision,event_id)<($3,$4::bigint))
            ORDER BY revision DESC,event_id DESC LIMIT $5
        ) h ON TRUE
        WHERE p.id=$1 AND p.author_id=$2
            AND NOT EXISTS (SELECT 1 FROM content_author_purges WHERE author_id=$2)
        ORDER BY h.revision DESC,h.event_id DESC`

	rows, err := s.db.QueryContext(ctx, query, id, author, beforeRevision, beforeEvent, PostHistoryPageSize+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]PostHistoryItem, 0, PostHistoryPageSize+1)
	found := false
	for rows.Next() {
		found = true
		var eventID, revision sql.NullInt64
		var state, visibility, operation sql.NullString
		var instant sql.NullTime
		if err := rows.Scan(&eventID, &revision, &state, &visibility, &operation, &instant); err != nil {
			return nil, err
		}

		if revision.Valid {
			items = append(items, PostHistoryItem{
				EventID:    eventID.Int64,
				Revision:   revision.Int64,
				State:      state.String,
				Visibility: visibility.String,
				Operation:  operation.String,
				ChangedAt:  instant.Time,
			})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrPostNotFound
	}

	return items, nil
}
