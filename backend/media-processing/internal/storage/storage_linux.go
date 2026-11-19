//go:build linux

package storage

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

const maxDepth = 32

var ErrStorageBusy = errors.New("media storage is busy")

type Store struct {
	mu     sync.RWMutex
	rootFD int
	closed bool
}

func Open(path string) (*Store, error) {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)

	if err != nil {
		return nil, fmt.Errorf("open media storage: %w", err)
	}

	var info unix.Stat_t

	if err := unix.Fstat(fd, &info); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("inspect media storage: %w", err)
	}

	if info.Uid != uint32(os.Geteuid()) || info.Mode&0022 != 0 {
		_ = unix.Close(fd)
		return nil, errors.New("media storage must be owned by the service and not writable by other users")
	}

	return &Store{rootFD: fd}, nil
}

// Delete removes one UUID directory without crossing mounts or following symlinks.
// All writers must use the same storage lock.
func (s *Store) Delete(id uuid.UUID) error {
	if id == uuid.Nil {
		return errors.New("invalid media id")
	}

	return s.WithWriteLock(func() error {
		return s.deleteLocked(id)
	})
}

// WithWriteLock serializes cooperating writers and cleaners for this storage root.
// Writers must not modify the storage outside the callback.
func (s *Store) WithWriteLock(operation func() error) error {
	if operation == nil {
		return errors.New("missing storage operation")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return errors.New("media storage is closed")
	}

	// A distinct open file description is needed for each flock, including
	// concurrent operations on the same Store.
	lockFD, err := unix.Openat(s.rootFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)

	if err != nil {
		return fmt.Errorf("open media storage lock: %w", err)
	}

	defer unix.Close(lockFD)

	if err := unix.Flock(lockFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return ErrStorageBusy
		}

		return fmt.Errorf("lock media storage: %w", err)
	}

	defer unix.Flock(lockFD, unix.LOCK_UN)

	return operation()
}

func (s *Store) deleteLocked(id uuid.UUID) error {
	name := id.String()
	fd, err := openDirectory(s.rootFD, name)

	if errors.Is(err, unix.ENOENT) {
		return s.syncRoot()
	}

	if err != nil {
		return fmt.Errorf("open media directory: %w", err)
	}

	if err := removeContents(fd, 0); err != nil {
		return fmt.Errorf("remove media contents: %w", err)
	}

	if err := unix.Unlinkat(s.rootFD, name, unix.AT_REMOVEDIR); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("remove media directory: %w", err)
	}

	return s.syncRoot()
}

func (s *Store) syncRoot() error {
	fd, err := openDirectory(s.rootFD, ".")

	if err != nil {
		return fmt.Errorf("open storage for sync: %w", err)
	}

	defer unix.Close(fd)

	if err := unix.Fsync(fd); err != nil {
		return fmt.Errorf("sync media storage: %w", err)
	}

	return nil
}

func openDirectory(parent int, name string) (int, error) {
	return unix.Openat2(parent, name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV,
	})
}

func removeContents(fd, depth int) error {
	file := os.NewFile(uintptr(fd), "media-directory")
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("invalid directory handle")
	}
	defer file.Close()

	if depth > maxDepth {
		return errors.New("media directory nesting limit exceeded")
	}

	for {
		names, err := file.Readdirnames(128)
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("read media directory: %w", err)
		}

		for _, name := range names {
			if err := removeEntry(fd, name, depth); err != nil {
				return err
			}
		}

		if errors.Is(err, io.EOF) {
			return nil
		}
	}
}

func removeEntry(parent int, name string, depth int) error {
	var info unix.Stat_t
	if err := unix.Fstatat(parent, name, &info, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("inspect media entry: %w", err)
	}

	if info.Mode&unix.S_IFMT == unix.S_IFDIR {
		child, err := openDirectory(parent, name)
		if err != nil {
			return fmt.Errorf("open media child directory: %w", err)
		}
		if err := removeContents(child, depth+1); err != nil {
			return err
		}
		if err := unix.Unlinkat(parent, name, unix.AT_REMOVEDIR); err != nil && !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("remove media child directory: %w", err)
		}
		return nil
	}

	if err := unix.Unlinkat(parent, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("remove media entry: %w", err)
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
	return unix.Close(s.rootFD)
}
