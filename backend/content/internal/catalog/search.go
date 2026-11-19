package catalog

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// PublicSearchCandidate is an internal result that still requires an auth/user check.
type PublicSearchCandidate struct {
	ID       uuid.UUID `json:"id"`
	AuthorID uuid.UUID `json:"author_id"`
	Kind     string    `json:"kind"`
	Title    string    `json:"title"`
}

// RecheckPublicSearch preserves candidate order and discards stale or private entries.
func (s *Store) RecheckPublicSearch(ctx context.Context, ids []uuid.UUID, query string) ([]PublicSearchCandidate, error) {
	if len(ids) > 50 || strings.TrimSpace(query) == "" || len(query) > 256 || !utf8.ValidString(query) || strings.ContainsRune(query, 0) {
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

	const querySQL = `SELECT p.id, p.author_id, p.media_kind, p.title
		FROM unnest($1::uuid[]) WITH ORDINALITY AS candidate(id, position)
		JOIN content_posts p ON p.id = candidate.id
		WHERE p.status = 'published' AND p.visibility = 'public'
			AND to_tsvector('simple', p.title) @@ plainto_tsquery('simple', $2)
		ORDER BY candidate.position`

	rows, err := s.db.QueryContext(ctx, querySQL, pq.Array(raw), query)

	if err != nil {
		return nil, fmt.Errorf("recheck public search: %w", err)
	}

	defer rows.Close()
	results := make([]PublicSearchCandidate, 0, len(ids))

	for rows.Next() {
		var candidate PublicSearchCandidate

		if err := rows.Scan(&candidate.ID, &candidate.AuthorID, &candidate.Kind, &candidate.Title); err != nil {
			return nil, fmt.Errorf("read public search result: %w", err)
		}

		results = append(results, candidate)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read public search results: %w", err)
	}

	return results, nil
}
