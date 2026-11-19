//go:build linux

package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

// InstallGuarded keeps the storage lock across the lease check and ledger update.
// Callbacks must use the supplied context and must not re-enter this Store.
func (s *Store) InstallGuarded(
	ctx context.Context,
	id uuid.UUID,
	files []InputFile,
	expected []InstalledFile,
	check func(context.Context) error,
	commit func(context.Context) error,
) error {
	if ctx == nil || id == uuid.Nil || len(files) == 0 || len(files) > 16 || len(files) != len(expected) || check == nil || commit == nil {
		return errors.New("invalid guarded media installation")
	}

	seen := make(map[string]struct{}, len(files))
	expectedByName := make(map[string]InstalledFile, len(expected))

	for _, item := range expected {
		if !validFilename(item.Name) || item.Size <= 0 || item.Size > 1<<40 {
			return errors.New("invalid expected media manifest")
		}

		if _, exists := expectedByName[item.Name]; exists {
			return errors.New("duplicate media filename")
		}

		expectedByName[item.Name] = item
		seen[item.Name] = struct{}{}
	}

	for _, file := range files {
		item, exists := expectedByName[file.Name]

		if !exists || file.Reader == nil || file.MaxBytes != item.Size {
			return errors.New("invalid media input")
		}

		delete(expectedByName, file.Name)
	}

	if len(expectedByName) != 0 {
		return errors.New("invalid media input")
	}

	return s.WithWriteLock(func() error {
		if err := check(ctx); err != nil {
			return err
		}

		fd, err := openDirectory(s.rootFD, id.String())

		switch {
		case err == nil:
			_ = unix.Close(fd)

			if err := s.verifySetLocked(ctx, id, expected, seen); err != nil {
				return err
			}
		case errors.Is(err, unix.ENOENT):
			installed, err := s.installSetLocked(ctx, id, files)

			if err != nil {
				return err
			}

			if !sameManifest(installed, expected) {
				return ErrSetMismatch
			}
		default:
			return fmt.Errorf("inspect media set: %w", err)
		}

		return commit(ctx)
	})
}

func sameManifest(actual, expected []InstalledFile) bool {
	if len(actual) != len(expected) {
		return false
	}

	items := make(map[string]InstalledFile, len(expected))

	for _, item := range expected {
		items[item.Name] = item
	}

	for _, item := range actual {
		if expected, exists := items[item.Name]; !exists || item != expected {
			return false
		}
	}

	return true
}
