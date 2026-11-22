package catalog

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

type PointWarning struct {
	LostPercent int       `json:"lost_percent"`
	CaseID      uuid.UUID `json:"case_id"`
	CreatedAt   time.Time `json:"created_at"`
}

type PointsBan struct {
	Tier   int        `json:"tier"`
	EndsAt *time.Time `json:"ends_at"`
}

type ModerationPoints struct {
	Warnings        []PointWarning `json:"warnings"`
	Ban             *PointsBan     `json:"ban,omitempty"`
	Balance         int            `json:"balance"`
	Initial         int            `json:"initial_points"`
	Maximum         int            `json:"maximum_points"`
	CommentsLimited bool           `json:"comments_limited"`
}

func (s *Store) Points(ctx context.Context, owner uuid.UUID) (ModerationPoints, error) {
	var points ModerationPoints
	const query = `SELECT balance,initial_points,maximum_points,comments_limited,b.tier,b.ends_at,
        COALESCE((SELECT json_agg(w ORDER BY w.lost_percent) FROM public.content_owner_point_notices($1) w),'[]')
        FROM public.content_owner_points($1) p
        LEFT JOIN LATERAL public.content_active_points_ban($1) b ON TRUE`

	var tier sql.NullInt64
	var endsAt *time.Time
	var warnings []byte
	err := s.db.QueryRowContext(ctx, query, owner).Scan(&points.Balance, &points.Initial, &points.Maximum, &points.CommentsLimited, &tier, &endsAt, &warnings)
	if errors.Is(err, sql.ErrNoRows) {
		return points, ErrPostNotFound
	}
	if err != nil {
		return points, err
	}
	if tier.Valid {
		points.Ban = &PointsBan{Tier: int(tier.Int64), EndsAt: endsAt}
	}

	return points, json.Unmarshal(warnings, &points.Warnings)
}

func (s *Store) ParticipationBanned(ctx context.Context, owner uuid.UUID) (bool, error) {
	const query = `SELECT EXISTS(SELECT 1 FROM public.content_active_points_ban($1))
     OR EXISTS(SELECT 1 FROM content_author_purges WHERE author_id=$1)`
	var banned bool
	err := s.db.QueryRowContext(ctx, query, owner).Scan(&banned)
	return banned, err
}

func (s *Store) ApplyProfilePointsEvent(ctx context.Context, target, owner uuid.UUID, operation, reason string) (bool, error) {
	var accepted bool
	err := s.db.QueryRowContext(ctx, `SELECT public.content_apply_profile_points($1,$2,$3,$4)`, target, owner, operation, reason).Scan(&accepted)
	return accepted, err
}
