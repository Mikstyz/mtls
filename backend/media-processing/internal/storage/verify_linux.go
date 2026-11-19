//go:build linux

package storage

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

var ErrSetMismatch = errors.New("installed media set does not match")

// VerifySet checks every expected file and synchronizes the already-installed set.
func (s *Store) VerifySet(ctx context.Context, id uuid.UUID, expected []InstalledFile) error {
	if ctx == nil || id == uuid.Nil || len(expected) == 0 || len(expected) > 16 {
		return errors.New("invalid media verification")
	}

	seen := make(map[string]struct{}, len(expected))

	for _, file := range expected {
		if !validFilename(file.Name) || file.Size < 0 || file.Size > 1<<40 {
			return errors.New("invalid media verification")
		}

		if _, exists := seen[file.Name]; exists {
			return errors.New("duplicate media filename")
		}

		seen[file.Name] = struct{}{}
	}

	return s.WithWriteLock(func() error {
		return s.verifySetLocked(ctx, id, expected, seen)
	})
}

func (s *Store) verifySetLocked(ctx context.Context, id uuid.UUID, expected []InstalledFile, seen map[string]struct{}) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	dirFD, err := openDirectory(s.rootFD, id.String())

	if err != nil {
		return fmt.Errorf("open media set: %w", err)
	}

	dir := os.NewFile(uintptr(dirFD), "media-set")

	if dir == nil {
		_ = unix.Close(dirFD)
		return errors.New("invalid media directory")
	}

	defer dir.Close()
	names, err := dir.Readdirnames(len(expected) + 1)

	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read media set: %w", err)
	}

	if len(names) != len(expected) {
		return ErrSetMismatch
	}

	for _, name := range names {
		if _, exists := seen[name]; !exists {
			return ErrSetMismatch
		}
	}

	for _, item := range expected {
		if err := verifyFile(ctx, dirFD, item); err != nil {
			return err
		}
	}

	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync media set: %w", err)
	}

	return s.syncRoot()
}

func verifyFile(ctx context.Context, parent int, expected InstalledFile) error {
	fd, err := unix.Openat2(parent, expected.Name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV,
	})

	if err != nil {
		return fmt.Errorf("open installed media: %w", err)
	}

	file := os.NewFile(uintptr(fd), "installed-media")

	if file == nil {
		_ = unix.Close(fd)
		return errors.New("invalid media file")
	}

	defer file.Close()
	info, err := file.Stat()

	if err != nil {
		return fmt.Errorf("inspect installed media: %w", err)
	}

	if !info.Mode().IsRegular() || info.Size() != expected.Size {
		return ErrSetMismatch
	}

	hash := sha256.New()
	size, err := io.Copy(hash, &contextReader{ctx: ctx, source: io.LimitReader(file, expected.Size+1)})

	if err != nil {
		return fmt.Errorf("verify installed media: %w", err)
	}

	if size != expected.Size || subtle.ConstantTimeCompare(hash.Sum(nil), expected.SHA256[:]) != 1 {
		return ErrSetMismatch
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync installed media: %w", err)
	}

	return nil
}
