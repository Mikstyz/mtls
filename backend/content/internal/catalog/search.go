package catalog

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"mtls/shared/searchtext"
)

// PublicSearchCandidate is an internal result that still requires an auth/user check.
type PublicSearchCandidate struct {
	ID           uuid.UUID  `json:"id"`
	AuthorID     uuid.UUID  `json:"author_id"`
	Kind         string     `json:"kind"`
	Title        string     `json:"title"`
	CoverMediaID *uuid.UUID `json:"cover_media_id,omitempty"`
}

// RecheckPublicSearch preserves candidate order and discards stale or private entries.
func (s *Store) RecheckPublicSearch(ctx context.Context, ids []uuid.UUID, query, prefix string) ([]PublicSearchCandidate, error) {
	if len(ids) > 50 || !searchtext.Valid(query, prefix) {
		return nil, ErrInvalidFilter
	}

	raw := make([]string, 0, len(ids))
	seen := make(map[uuid.UUID]struct{}, len(ids))

	for _, id := range ids {
		if id == uuid.Nil {
			return nil, ErrInvalidFilter
		}

		if _, exists := seen[id]; exists {
			return nil, ErrInvalidFilter
		}

		seen[id] = struct{}{}
		raw = append(raw, id.String())
	}

	if len(raw) == 0 {
		return []PublicSearchCandidate{}, nil
	}

	const querySQL = `SELECT p.id, p.author_id, p.media_kind, p.title,
		` + postCoverMedia + `
		FROM unnest($1::uuid[]) WITH ORDINALITY AS candidate(id, position)
		JOIN content_posts p ON p.id = candidate.id
		WHERE p.status = 'published' AND p.hidden_by_case IS NULL AND p.visibility = 'public'
			AND NOT EXISTS (SELECT 1 FROM content_author_purges a WHERE a.author_id = p.author_id)
			AND to_tsvector('simple', p.title) @@ ` + searchtext.SQLQuery + `
		ORDER BY candidate.position`

	rows, err := s.db.QueryContext(ctx, querySQL, pq.Array(raw), query, prefix)

	if err != nil {
		return nil, fmt.Errorf("recheck public search: %w", err)
	}

	defer rows.Close()
	results := make([]PublicSearchCandidate, 0, len(ids))

	for rows.Next() {
		var candidate PublicSearchCandidate
		var cover uuid.NullUUID

		if err := rows.Scan(&candidate.ID, &candidate.AuthorID, &candidate.Kind, &candidate.Title, &cover); err != nil {
			return nil, fmt.Errorf("read public search result: %w", err)
		}

		if cover.Valid {
			candidate.CoverMediaID = &cover.UUID
		}

		results = append(results, candidate)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read public search results: %w", err)
	}

	return results, nil
}
