package lifecycle

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// CheckPhotoInput verifies the exact uploaded bytes for a current lease or its replay.
func (s *Store) CheckPhotoInput(ctx context.Context, id, lease uuid.UUID, size int64, digest [32]byte) error {
	return s.checkInput(ctx, id, lease, "photo", size, digest, 32<<20)
}

func (s *Store) checkInput(ctx context.Context, id, lease uuid.UUID, kind string, size int64, digest [32]byte, maximum int64) error {
	if id == uuid.Nil || lease == uuid.Nil || size < 1 || size > maximum {
		return ErrInvalid
	}

	const query = `SELECT EXISTS (
		SELECT 1 FROM media_assets a JOIN media_uploads u ON u.asset_id = a.id
		WHERE a.id = $1 AND a.kind = $5 AND u.uploaded AND u.byte_size = $3 AND u.sha256 = $4
			AND ((a.state = 'processing' AND a.lease_token = $2 AND a.lease_until > clock_timestamp())
				OR (a.state = 'processed' AND a.processed_lease_token = $2))
	)`

	var allowed bool

	if err := s.db.QueryRowContext(ctx, query, id, lease, size, digest[:], kind).Scan(&allowed); err != nil {
		return fmt.Errorf("check media input: %w", err)
	}

	if !allowed {
		return ErrConflict
	}

	return nil
}
