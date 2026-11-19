//go:build linux

package quarantine

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
	"os"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

func (s *Store) verify(ctx context.Context, id uuid.UUID, size int64, expected [32]byte) error {
	fd, err := unix.Openat2(s.fd, id.String(), &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV,
	})

	if err != nil {
		return fmt.Errorf("open existing quarantine upload: %w", err)
	}

	file := os.NewFile(uintptr(fd), "quarantine-upload")

	if file == nil {
		_ = unix.Close(fd)
		return ErrMismatch
	}

	defer file.Close()
	info, err := file.Stat()

	if err != nil {
		return fmt.Errorf("inspect quarantine upload: %w", err)
	}

	if !info.Mode().IsRegular() || info.Size() != size {
		return ErrMismatch
	}

	hash := sha256.New()
	read, err := io.Copy(hash, &contextReader{ctx: ctx, source: io.LimitReader(file, size+1)})

	if err != nil {
		return fmt.Errorf("verify quarantine upload: %w", err)
	}

	if read != size || subtle.ConstantTimeCompare(hash.Sum(nil), expected[:]) != 1 {
		return ErrMismatch
	}

	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync existing quarantine upload: %w", err)
	}

	return nil
}
