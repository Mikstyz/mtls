//go:build linux

package quarantine

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

// CleanPartials removes abandoned fallback uploads but skips live writers.
func (s *Store) CleanPartials(ctx context.Context, limit int) (int, error) {
	if ctx == nil || limit < 1 || limit > 100 {
		return 0, ErrInvalid
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return 0, errors.New("quarantine is closed")
	}

	var removed int
	err := s.withLock(func() error {
		var err error
		removed, err = s.cleanPartialsLocked(ctx, limit)
		return err
	})

	return removed, err
}

func (s *Store) cleanPartialsLocked(ctx context.Context, limit int) (removed int, resultErr error) {
	fd, err := unix.Openat(s.fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)

	if err != nil {
		return 0, fmt.Errorf("open quarantine directory: %w", err)
	}

	dir := os.NewFile(uintptr(fd), "quarantine")

	if dir == nil {
		_ = unix.Close(fd)
		return 0, errors.New("invalid quarantine directory")
	}

	defer dir.Close()
	defer func() {
		if removed > 0 || resultErr == nil {
			resultErr = errors.Join(resultErr, s.syncRoot())
		}
	}()

	for {
		if err := ctx.Err(); err != nil {
			return removed, err
		}

		names, readErr := dir.Readdirnames(128)

		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return removed, fmt.Errorf("read quarantine directory: %w", readErr)
		}

		for _, name := range names {
			if err := ctx.Err(); err != nil {
				return removed, err
			}

			text, ok := strings.CutPrefix(name, ".partial-")

			if !ok {
				continue
			}

			id, err := uuid.Parse(text)

			if err != nil || id == uuid.Nil || id.String() != text {
				continue
			}

			deleted, err := s.removePartial(name)

			if err != nil {
				return removed, err
			}

			if deleted {
				removed++
			}

			if removed == limit {
				return removed, nil
			}
		}

		if errors.Is(readErr, io.EOF) {
			return removed, nil
		}
	}
}

func (s *Store) removePartial(name string) (bool, error) {
	fd, err := unix.Openat2(s.fd, name, &unix.OpenHow{
		Flags:   unix.O_RDWR | unix.O_NONBLOCK | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV,
	})

	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}

	if err != nil {
		return false, fmt.Errorf("open partial upload: %w", err)
	}

	defer unix.Close(fd)

	if err := validatePrivateFile(fd); err != nil {
		return false, err
	}

	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return false, nil
		}

		return false, fmt.Errorf("lock partial upload: %w", err)
	}

	defer unix.Flock(fd, unix.LOCK_UN)

	if err := unix.Unlinkat(s.fd, name, 0); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}

		return false, fmt.Errorf("remove partial upload: %w", err)
	}

	return true, nil
}
