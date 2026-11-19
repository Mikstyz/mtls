//go:build linux

// Package quarantine stores private uploads before validation and processing.
package quarantine

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

var (
	ErrInvalid  = errors.New("invalid quarantine operation")
	ErrMismatch = errors.New("upload size or digest mismatch")
	ErrBusy     = errors.New("quarantine is busy")
)

type Store struct {
	mu     sync.RWMutex
	fd     int
	closed bool
}

// Open opens a private directory that must not be served by the media service.
func Open(path string) (*Store, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)

	if err != nil {
		return nil, fmt.Errorf("open quarantine: %w", err)
	}

	var info unix.Stat_t

	if err := unix.Fstat(fd, &info); err != nil || info.Uid != uint32(os.Geteuid()) || info.Mode&0077 != 0 {
		_ = unix.Close(fd)
		return nil, errors.New("quarantine directory must be private and owned by the service")
	}

	return &Store{fd: fd}, nil
}

// Accept streams into an anonymous file, verifies it, and publishes it under id.
// The guard runs before reading and again under the directory lock before publication.
// The commit callback runs after filesystem sync while holding the same lock.
// Callbacks must not re-enter this Store.
func (s *Store) Accept(ctx context.Context, id uuid.UUID, size int64, expected [32]byte, source io.Reader, guard, commit func(context.Context) error) error {
	if ctx == nil || id == uuid.Nil || size < 1 || size > 1<<40 || source == nil || guard == nil || commit == nil {
		return ErrInvalid
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return errors.New("quarantine is closed")
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	if err := guard(ctx); err != nil {
		return err
	}

	fd, partial, err := s.createUpload()

	if err != nil {
		return err
	}

	file := os.NewFile(uintptr(fd), "quarantine-upload")

	if file == nil {
		_ = unix.Close(fd)
		return errors.New("invalid quarantine file")
	}

	defer file.Close()

	if partial != "" {
		defer unix.Flock(fd, unix.LOCK_UN)
		defer unix.Unlinkat(s.fd, partial, 0)
	}

	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(file, hash), &contextReader{ctx: ctx, source: io.LimitReader(source, size+1)})

	if err != nil {
		return fmt.Errorf("write quarantine upload: %w", err)
	}

	if written != size || subtle.ConstantTimeCompare(hash.Sum(nil), expected[:]) != 1 {
		return ErrMismatch
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync quarantine upload: %w", err)
	}

	return s.withLock(func() error {
		if err := guard(ctx); err != nil {
			return err
		}

		if err := ctx.Err(); err != nil {
			return err
		}

		var err error

		if partial == "" {
			err = unix.Linkat(fd, "", s.fd, id.String(), unix.AT_EMPTY_PATH)

			if errors.Is(err, unix.EPERM) || errors.Is(err, unix.ENOENT) {
				path := "/proc/self/fd/" + strconv.Itoa(fd)
				err = unix.Linkat(unix.AT_FDCWD, path, s.fd, id.String(), unix.AT_SYMLINK_FOLLOW)
			}
		} else {
			err = unix.Renameat2(s.fd, partial, s.fd, id.String(), unix.RENAME_NOREPLACE)
		}

		if errors.Is(err, unix.EEXIST) {
			if err := s.verify(ctx, id, size, expected); err != nil {
				return err
			}
		} else if err != nil {
			return fmt.Errorf("publish quarantine upload: %w", err)
		}

		if err := s.syncRoot(); err != nil {
			return err
		}

		return commit(ctx)
	})
}

// Read opens a completed upload; possession of its ID does not grant access.
func (s *Store) Read(id uuid.UUID) (*os.File, error) {
	if id == uuid.Nil {
		return nil, ErrInvalid
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, errors.New("quarantine is closed")
	}

	fd, err := unix.Openat2(s.fd, id.String(), &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV,
	})

	if err != nil {
		return nil, fmt.Errorf("open quarantine upload: %w", err)
	}

	file := os.NewFile(uintptr(fd), "quarantine-upload")

	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("invalid quarantine file")
	}

	info, err := file.Stat()

	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, errors.New("invalid quarantine upload")
	}

	return file, nil
}

// Remove serializes the state check and deletion with publication.
func (s *Store) Remove(ctx context.Context, id uuid.UUID, guard func(context.Context) error) error {
	if ctx == nil || id == uuid.Nil || guard == nil {
		return ErrInvalid
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return errors.New("quarantine is closed")
	}

	return s.withLock(func() error {
		if err := guard(ctx); err != nil {
			return err
		}

		if err := ctx.Err(); err != nil {
			return err
		}

		if err := unix.Unlinkat(s.fd, id.String(), 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("remove quarantine upload: %w", err)
		}

		return s.syncRoot()
	})
}

func (s *Store) withLock(fn func() error) error {
	fd, err := unix.Openat(s.fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)

	if err != nil {
		return fmt.Errorf("open quarantine lock: %w", err)
	}

	defer unix.Close(fd)

	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return ErrBusy
		}

		return fmt.Errorf("lock quarantine: %w", err)
	}

	defer unix.Flock(fd, unix.LOCK_UN)
	return fn()
}

func (s *Store) syncRoot() error {
	if err := unix.Fsync(s.fd); err != nil {
		return fmt.Errorf("sync quarantine: %w", err)
	}

	return nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	s.closed = true
	return unix.Close(s.fd)
}

type contextReader struct {
	ctx    context.Context
	source io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}

	return r.source.Read(p)
}
