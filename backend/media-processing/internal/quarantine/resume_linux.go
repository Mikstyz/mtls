//go:build linux

package quarantine

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

func resumeName(id uuid.UUID) string {
	return ".resume-" + id.String()
}

// Append keeps the file private until the reserved size and digest have been verified.
func (s *Store) Append(ctx context.Context, id uuid.UUID, chunk Chunk, source io.Reader, guard, commit func(context.Context) error) (int64, error) {
	if ctx == nil || id == uuid.Nil || chunk.Total < 1 || chunk.Total > 1<<40 ||
		chunk.Offset < 0 || chunk.Offset > chunk.Total || chunk.Length < 0 ||
		(chunk.Length == 0 && chunk.Offset != chunk.Total) ||
		chunk.Length > MaxChunkBytes || chunk.Length > chunk.Total-chunk.Offset ||
		source == nil || guard == nil || commit == nil {
		return 0, ErrInvalid
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return 0, errors.New("quarantine is closed")
	}

	var file *os.File
	var recovered bool
	name := resumeName(id)

	err := s.withLock(func() error {
		if err := guard(ctx); err != nil {
			return err
		}

		var stat unix.Stat_t
		err := unix.Fstatat(s.fd, id.String(), &stat, unix.AT_SYMLINK_NOFOLLOW)
		switch {
		case err == nil:
			if err := s.verify(ctx, id, chunk.Total, chunk.Digest); err != nil {
				return err
			}
			if err := s.syncRoot(); err != nil {
				return err
			}
			if err := commit(ctx); err != nil {
				return err
			}

			recovered = true
			return nil
		case !errors.Is(err, unix.ENOENT):
			return err
		}

		flags := unix.O_RDWR
		if chunk.Offset == 0 {
			flags |= unix.O_CREAT
		}

		file, err = s.openLockedFile(name, flags)
		if errors.Is(err, unix.ENOENT) {
			return ErrOffset
		}
		return err
	})
	if err != nil {
		return 0, err
	}
	if recovered {
		return chunk.Total, nil
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return 0, err
	}
	if info.Size() != chunk.Offset {
		return info.Size(), ErrOffset
	}
	if _, err := file.Seek(chunk.Offset, io.SeekStart); err != nil {
		return chunk.Offset, err
	}

	written, err := io.Copy(file, &contextReader{ctx: ctx, source: io.LimitReader(source, chunk.Length+1)})
	if err == nil && written != chunk.Length {
		err = ErrMismatch
	}
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		err = guard(ctx)
	}
	if err != nil {
		return chunk.Offset, errors.Join(err, file.Truncate(chunk.Offset), file.Sync())
	}

	offset := chunk.Offset + chunk.Length
	if err := file.Sync(); err != nil {
		return chunk.Offset, errors.Join(err, file.Truncate(chunk.Offset), file.Sync())
	}
	if offset < chunk.Total {
		return offset, s.syncRoot()
	}

	hash := sha256.New()
	reader := io.NewSectionReader(file, 0, chunk.Total)
	if _, err := io.Copy(hash, &contextReader{ctx: ctx, source: reader}); err != nil {
		return chunk.Offset, errors.Join(err, file.Truncate(chunk.Offset), file.Sync())
	}

	matches := subtle.ConstantTimeCompare(hash.Sum(nil), chunk.Digest[:]) == 1
	err = s.withLock(func() error {
		if err := guard(ctx); err != nil {
			return err
		}
		if !matches {
			if err := unix.Unlinkat(s.fd, name, 0); err != nil {
				return err
			}
			if err := s.syncRoot(); err != nil {
				return err
			}

			return ErrMismatch
		}

		err := unix.Renameat2(s.fd, name, s.fd, id.String(), unix.RENAME_NOREPLACE)
		if errors.Is(err, unix.EEXIST) {
			if err := s.verify(ctx, id, chunk.Total, chunk.Digest); err != nil {
				return err
			}
			if err := unix.Unlinkat(s.fd, name, 0); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}

		if err := s.syncRoot(); err != nil {
			return err
		}
		return commit(ctx)
	})
	return offset, err
}

// UploadOffset reports the on-disk prefix while holding the same lock as Append.
func (s *Store) UploadOffset(id uuid.UUID) (int64, error) {
	if id == uuid.Nil {
		return 0, ErrInvalid
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return 0, errors.New("quarantine is closed")
	}

	var offset int64
	err := s.withLock(func() error {
		var stat unix.Stat_t
		err := unix.Fstatat(s.fd, id.String(), &stat, unix.AT_SYMLINK_NOFOLLOW)
		if err == nil {
			if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0077 != 0 {
				return ErrInvalid
			}
			offset = stat.Size
			return nil
		}
		if !errors.Is(err, unix.ENOENT) {
			return err
		}

		file, err := s.openLockedFile(resumeName(id), unix.O_RDONLY)
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		if err != nil {
			return err
		}
		defer file.Close()

		info, err := file.Stat()
		if err != nil {
			return err
		}

		offset = info.Size()
		return nil
	})
	return offset, err
}

func (s *Store) openLockedFile(name string, flags int) (*os.File, error) {
	var mode uint64
	if flags&unix.O_CREAT != 0 {
		mode = 0600
	}

	fd, err := unix.Openat2(s.fd, name, &unix.OpenHow{
		Flags:   uint64(flags | unix.O_NONBLOCK | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Mode:    mode,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV,
	})
	if err != nil {
		return nil, err
	}
	if err := validatePrivateFile(fd); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = unix.Close(fd)
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrBusy
		}

		return nil, fmt.Errorf("lock resumable upload: %w", err)
	}

	return os.NewFile(uintptr(fd), name), nil
}
