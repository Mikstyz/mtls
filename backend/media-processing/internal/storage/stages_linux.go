//go:build linux

package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

// CleanStages removes abandoned staging directories under the cooperating storage lock.
func (s *Store) CleanStages(ctx context.Context, limit int) (int, error) {
	if ctx == nil || limit < 1 || limit > 100 {
		return 0, errors.New("invalid staging cleanup")
	}

	var removed int
	err := s.WithWriteLock(func() error {
		var err error
		removed, err = s.cleanStagesLocked(ctx, limit)
		return err
	})

	return removed, err
}

func (s *Store) cleanStagesLocked(ctx context.Context, limit int) (removed int, resultErr error) {
	fd, err := openDirectory(s.rootFD, ".")

	if err != nil {
		return 0, fmt.Errorf("open storage directory: %w", err)
	}

	root := os.NewFile(uintptr(fd), "media-storage")

	if root == nil {
		_ = unix.Close(fd)
		return 0, errors.New("invalid storage directory")
	}

	defer root.Close()
	defer func() {
		if removed > 0 || resultErr == nil {
			if err := root.Sync(); err != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("sync storage cleanup: %w", err))
			}
		}
	}()

	for {
		if err := ctx.Err(); err != nil {
			return removed, err
		}

		names, readErr := root.Readdirnames(128)

		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return removed, fmt.Errorf("read storage directory: %w", readErr)
		}

		for _, name := range names {
			if err := ctx.Err(); err != nil {
				return removed, err
			}

			idText, ok := strings.CutPrefix(name, ".stage-")

			if !ok {
				continue
			}

			id, err := uuid.Parse(idText)

			if err != nil || id == uuid.Nil || id.String() != idText {
				continue
			}

			stageFD, err := openDirectory(fd, name)

			if errors.Is(err, unix.ENOENT) {
				continue
			}

			if err != nil {
				return removed, fmt.Errorf("open abandoned staging directory: %w", err)
			}

			if err := removeFiles(stageFD); err != nil {
				return removed, fmt.Errorf("clean abandoned staging directory: %w", err)
			}

			if err := unix.Unlinkat(fd, name, unix.AT_REMOVEDIR); err != nil && !errors.Is(err, unix.ENOENT) {
				return removed, fmt.Errorf("remove abandoned staging directory: %w", err)
			}

			removed++

			if removed == limit {
				return removed, nil
			}
		}

		if errors.Is(readErr, io.EOF) {
			return removed, nil
		}
	}
}
