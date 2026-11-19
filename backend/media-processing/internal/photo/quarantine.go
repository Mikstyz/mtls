package photo

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/google/uuid"
	"mtls/media-processing/internal/imageprep"
	"mtls/media-processing/internal/lifecycle"
	"mtls/media-processing/internal/quarantine"
	"mtls/media-processing/internal/storage"
)

// StoreQuarantinedPhoto processes the private upload associated with a lease.
// A successful result does not grant permission to access the prepared files.
func StoreQuarantinedPhoto(ctx context.Context, store *storage.Store, private *quarantine.Store, processor *Processor, ledger *lifecycle.Store, id, lease uuid.UUID, maxEdge int) error {
	if ctx == nil || store == nil || private == nil || processor == nil || ledger == nil || id == uuid.Nil || lease == uuid.Nil || maxEdge < 1 || maxEdge > 2048 {
		return errors.New("invalid quarantined photo")
	}

	release, err := processor.acquire(ctx)

	if err != nil {
		return err
	}

	defer release()

	if err := ledger.CheckPhotoLease(ctx, id, lease); err != nil {
		return err
	}

	file, err := private.Read(id)

	if err != nil {
		return fmt.Errorf("open quarantined photo: %w", err)
	}

	defer file.Close()

	input, err := io.ReadAll(io.LimitReader(file, imageprep.MaxInputBytes+1))

	if err != nil {
		return fmt.Errorf("read quarantined photo: %w", err)
	}

	if len(input) == 0 || len(input) > imageprep.MaxInputBytes {
		return errors.New("invalid quarantined photo size")
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	return storePhotoLocked(ctx, store, processor, ledger, id, lease, input, maxEdge)
}
