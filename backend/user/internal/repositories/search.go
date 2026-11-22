package repositories

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"mtls/shared/searchtext"
	"mtls/user/internal/models"
)

// SearchCandidates rechecks names against the authoritative active-user table.
func (r *userRepo) SearchCandidates(ctx context.Context, ids []uuid.UUID, query, prefix string) ([]models.SearchUser, error) {
	if len(ids) == 0 {
		return []models.SearchUser{}, nil
	}

	raw := make([]string, 0, len(ids))
	for _, id := range ids {
		raw = append(raw, id.String())
	}

	const sqlQuery = `SELECT u.id, u.nickname
        FROM unnest($1::uuid[]) WITH ORDINALITY AS candidate(id, position)
        JOIN users AS u ON u.id = candidate.id
        WHERE to_tsvector('simple', u.nickname) @@ ` + searchtext.SQLQuery + `
        ORDER BY candidate.position`
	rows, err := r.db.QueryContext(ctx, sqlQuery, pq.Array(raw), query, prefix)
	if err != nil {
		return nil, fmt.Errorf("recheck user search candidates: %w", err)
	}
	defer rows.Close()

	users := make([]models.SearchUser, 0, len(ids))
	for rows.Next() {
		var user models.SearchUser
		if err := rows.Scan(&user.ID, &user.Nickname); err != nil {
			return nil, fmt.Errorf("read user search candidate: %w", err)
		}
		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read user search candidates: %w", err)
	}

	return users, nil
}

// ExistingProfiles returns only IDs still present in the user service.
func (r *userRepo) ExistingProfiles(ctx context.Context, ids []uuid.UUID) ([]uuid.UUID, error) {
	if len(ids) == 0 {
		return []uuid.UUID{}, nil
	}

	if len(ids) > 50 {
		return nil, fmt.Errorf("too many profile IDs")
	}

	raw := make([]string, 0, len(ids))

	for _, id := range ids {
		if id == uuid.Nil {
			return nil, fmt.Errorf("invalid profile ID")
		}

		raw = append(raw, id.String())
	}

	rows, err := r.db.QueryContext(ctx, `SELECT id FROM users WHERE id = ANY($1::uuid[])`, pq.Array(raw))

	if err != nil {
		return nil, fmt.Errorf("check user profiles: %w", err)
	}

	defer rows.Close()
	profiles := make([]uuid.UUID, 0, len(ids))

	for rows.Next() {
		var id uuid.UUID

		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("read user profiles: %w", err)
		}

		profiles = append(profiles, id)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read user profiles: %w", err)
	}

	return profiles, nil
}
