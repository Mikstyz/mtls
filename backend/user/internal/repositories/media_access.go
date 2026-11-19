package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// MediaAccessOwner checks the current policy and both profiles in one snapshot.
// For a post request, content supplies the additional publication decision.
func (r *userRepo) MediaAccessOwner(ctx context.Context, mediaID, viewerID uuid.UUID, postScoped bool) (uuid.UUID, bool, error) {
	if mediaID == uuid.Nil || viewerID == uuid.Nil {
		return uuid.Nil, false, nil
	}

	const query = `SELECT permission.owner_id FROM media_permissions AS permission
        JOIN users AS owner ON owner.id = permission.owner_id
        JOIN users AS viewer ON viewer.id = $2
        WHERE permission.media_id = $1 AND permission.ready AND permission.revoked_at IS NULL
            AND ($3 OR permission.visibility = 'public' OR permission.owner_id = viewer.id OR EXISTS (
                SELECT 1 FROM media_permission_grants AS access_grant
                WHERE access_grant.media_id = permission.media_id AND access_grant.user_id = viewer.id
            ))`

	var owner uuid.UUID
	if err := r.db.QueryRowContext(ctx, query, mediaID, viewerID, postScoped).Scan(&owner); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return uuid.Nil, false, nil
		}
		return uuid.Nil, false, fmt.Errorf("check media access: %w", err)
	}

	return owner, true, nil
}

// ReadyMediaKind returns processing metadata for a still-ready owned asset.
func (r *userRepo) ReadyMediaKind(ctx context.Context, owner, media uuid.UUID) (string, error) {
	const query = `SELECT COALESCE(media_kind, '') FROM media_permissions
		WHERE media_id = $1 AND owner_id = $2 AND ready AND revoked_at IS NULL`

	var kind string
	err := r.db.QueryRowContext(ctx, query, media, owner).Scan(&kind)
	return kind, err
}
