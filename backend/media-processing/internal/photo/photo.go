package photo

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"

	"github.com/google/uuid"
	"mtls/media-processing/internal/imageprep"
	"mtls/media-processing/internal/lifecycle"
	"mtls/media-processing/internal/storage"
)

// StorePhoto records a private processed photo without granting access.
// Its caller owns authorization, malware scanning and the ready state.
func StorePhoto(ctx context.Context, store *storage.Store, processor *Processor, ledger *lifecycle.Store, id, lease uuid.UUID, input []byte, maxEdge int) error {
	if ctx == nil || store == nil || processor == nil || ledger == nil || id == uuid.Nil || lease == uuid.Nil ||
		len(input) == 0 || len(input) > imageprep.MaxInputBytes || maxEdge < 1 || maxEdge > 2048 {
		return errors.New("invalid photo")
	}

	release, err := processor.acquire(ctx)

	if err != nil {
		return err
	}

	defer release()

	return storePhotoLocked(ctx, store, processor, ledger, id, lease, bytes.Clone(input), maxEdge)
}

func storePhotoLocked(ctx context.Context, store *storage.Store, processor *Processor, ledger *lifecycle.Store, id, lease uuid.UUID, original []byte, maxEdge int) error {
	digest := sha256.Sum256(original)

	if err := ledger.CheckPhotoInput(ctx, id, lease, int64(len(original)), digest); err != nil {
		return err
	}

	preview, err := processor.prepareLocked(ctx, original, maxEdge)

	if err != nil {
		return err
	}

	format := "png"

	if len(original) >= 2 && original[0] == 0xff && original[1] == 0xd8 {
		format = "jpg"
	}

	return installPhoto(ctx, store, ledger, id, lease, original, preview, format)
}
