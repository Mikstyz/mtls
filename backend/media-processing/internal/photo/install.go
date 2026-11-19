package photo

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"

	"github.com/google/uuid"
	"mtls/media-processing/internal/lifecycle"
	"mtls/media-processing/internal/storage"
)

// installPhoto coordinates one local storage root with the processing ledger.
// A processed state does not itself grant access to a file.
func installPhoto(ctx context.Context, store *storage.Store, ledger *lifecycle.Store, id, lease uuid.UUID, original, preview []byte, format string) error {
	if ctx == nil || store == nil || ledger == nil || id == uuid.Nil || lease == uuid.Nil ||
		(format != "jpg" && format != "png") || len(original) == 0 || len(preview) == 0 ||
		len(original) > 32<<20 || len(preview) > 32<<20 {
		return errors.New("invalid photo installation")
	}

	originalName := "original." + format
	previewName := "preview." + format
	expected := []storage.InstalledFile{
		{Name: originalName, Size: int64(len(original)), SHA256: sha256.Sum256(original)},
		{Name: previewName, Size: int64(len(preview)), SHA256: sha256.Sum256(preview)},
	}
	files := []storage.InputFile{
		{Name: originalName, Reader: bytes.NewReader(original), MaxBytes: int64(len(original))},
		{Name: previewName, Reader: bytes.NewReader(preview), MaxBytes: int64(len(preview))},
	}
	variants := []lifecycle.Variant{
		{Name: originalName, Size: expected[0].Size, SHA256: expected[0].SHA256},
		{Name: previewName, Size: expected[1].Size, SHA256: expected[1].SHA256},
	}

	return store.InstallGuarded(ctx, id, files, expected,
		func(ctx context.Context) error {
			return ledger.CheckPhotoLease(ctx, id, lease)
		},
		func(ctx context.Context) error {
			return ledger.MarkPhotoProcessed(ctx, id, lease, variants)
		},
	)
}
