//go:build linux

package quarantine

import (
	"errors"
	"fmt"
	"os"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

func (s *Store) createUpload() (int, string, error) {
	fd, err := unix.Openat(s.fd, ".", unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, 0600)

	if err == nil {
		if err := validatePrivateFile(fd); err != nil {
			_ = unix.Close(fd)
			return -1, "", err
		}

		return fd, "", nil
	}

	if !errors.Is(err, unix.EOPNOTSUPP) && !errors.Is(err, unix.EINVAL) &&
		!errors.Is(err, unix.ENOSYS) && !errors.Is(err, unix.EISDIR) {
		return -1, "", fmt.Errorf("create anonymous upload: %w", err)
	}

	return s.createNamedPartial()
}

// NewPartial keeps a named private file locked while an isolated tool needs its path.
// CleanPartials can reclaim the file after a worker crash.
func (s *Store) NewPartial() (*os.File, func(), error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, nil, errors.New("quarantine is closed")
	}
	fd, name, err := s.createNamedPartial()
	if err != nil {
		return nil, nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	return file, func() {
		s.mu.RLock()
		defer s.mu.RUnlock()
		defer file.Close()
		if s.closed {
			return
		}
		_ = unix.Unlinkat(s.fd, name, 0)
	}, nil
}

func (s *Store) createNamedPartial() (int, string, error) {
	id, err := uuid.NewRandom()

	if err != nil {
		return -1, "", fmt.Errorf("generate partial upload ID: %w", err)
	}

	name := ".partial-" + id.String()
	fd := -1

	err = s.withLock(func() error {
		var err error
		fd, err = unix.Openat2(s.fd, name, &unix.OpenHow{
			Flags:   unix.O_CREAT | unix.O_EXCL | unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW,
			Mode:    0600,
			Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV,
		})

		if err != nil {
			return fmt.Errorf("create partial upload: %w", err)
		}

		if err := validatePrivateFile(fd); err != nil {
			_ = unix.Close(fd)
			_ = unix.Unlinkat(s.fd, name, 0)
			fd = -1
			return err
		}

		if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
			_ = unix.Close(fd)
			_ = unix.Unlinkat(s.fd, name, 0)
			fd = -1
			return fmt.Errorf("lock partial upload: %w", err)
		}

		return nil
	})

	if err != nil {
		return -1, "", err
	}

	return fd, name, nil
}

func validatePrivateFile(fd int) error {
	var info unix.Stat_t

	if err := unix.Fstat(fd, &info); err != nil || info.Mode&unix.S_IFMT != unix.S_IFREG ||
		info.Uid != uint32(os.Geteuid()) || info.Mode&0077 != 0 {
		return errors.New("quarantine file must be private and owned by the service")
	}

	return nil
}
