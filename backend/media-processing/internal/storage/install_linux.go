//go:build linux

package storage

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

var ErrFileTooLarge = errors.New("media file exceeds size limit")

type InputFile struct {
	Name     string
	Reader   io.Reader
	MaxBytes int64
}

type InstalledFile struct {
	Name   string
	Size   int64
	SHA256 [32]byte
}

// InstallSet publishes a prepared set atomically; it never overwrites an asset.
// Callers must verify the files and authorize access separately before use.
func (s *Store) InstallSet(ctx context.Context, id uuid.UUID, files []InputFile) ([]InstalledFile, error) {
	if ctx == nil || id == uuid.Nil || len(files) == 0 || len(files) > 16 {
		return nil, errors.New("invalid media installation")
	}

	seen := make(map[string]struct{}, len(files))

	for _, file := range files {
		if !validFilename(file.Name) || file.Reader == nil || file.MaxBytes < 1 || file.MaxBytes > 1<<40 {
			return nil, errors.New("invalid media installation")
		}

		if _, exists := seen[file.Name]; exists {
			return nil, errors.New("duplicate media filename")
		}

		seen[file.Name] = struct{}{}
	}

	var installed []InstalledFile
	err := s.WithWriteLock(func() error {
		var err error
		installed, err = s.installSetLocked(ctx, id, files)
		return err
	})

	return installed, err
}

func validFilename(name string) bool {
	switch name {
	case "original.jpg", "preview.jpg", "original.png", "preview.png",
		"poster.jpg", "poster-25.jpg", "poster-60.jpg",
		"original.mp4", "720p.mp4", "1080p.mp4", "1440p.mp4", "2160p.mp4",
		"adaptive.m3u8", "720p.m3u8", "1080p.m3u8", "1440p.m3u8", "2160p.m3u8":
		return true
	default:
		return false
	}
}

func (s *Store) installSetLocked(ctx context.Context, id uuid.UUID, files []InputFile) (result []InstalledFile, resultErr error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	stageID, err := uuid.NewRandom()

	if err != nil {
		return nil, fmt.Errorf("generate temporary directory: %w", err)
	}

	stage := ".stage-" + stageID.String()

	if err := unix.Mkdirat(s.rootFD, stage, 0700); err != nil {
		return nil, fmt.Errorf("create media staging directory: %w", err)
	}

	defer func() {
		fd, err := openDirectory(s.rootFD, stage)

		if errors.Is(err, unix.ENOENT) {
			return
		}

		if err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("open staging cleanup: %w", err))
			return
		}

		if err := removeFiles(fd); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("clean staging directory: %w", err))
			return
		}

		if err := unix.Unlinkat(s.rootFD, stage, unix.AT_REMOVEDIR); err != nil && !errors.Is(err, unix.ENOENT) {
			resultErr = errors.Join(resultErr, fmt.Errorf("remove staging directory: %w", err))
		}
	}()

	dirFD, err := openDirectory(s.rootFD, stage)

	if err != nil {
		return nil, fmt.Errorf("open staging directory: %w", err)
	}

	defer unix.Close(dirFD)
	result = make([]InstalledFile, 0, len(files))

	for _, input := range files {
		item, err := writePreparedFile(ctx, dirFD, input)

		if err != nil {
			return nil, err
		}

		result = append(result, item)
	}

	if err := unix.Fsync(dirFD); err != nil {
		return nil, fmt.Errorf("sync staging directory: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if err := unix.Renameat2(s.rootFD, stage, s.rootFD, id.String(), unix.RENAME_NOREPLACE); err != nil {
		return nil, fmt.Errorf("install media set: %w", err)
	}

	rootFD, err := openDirectory(s.rootFD, ".")

	if err != nil {
		return nil, fmt.Errorf("open storage directory: %w", err)
	}

	defer unix.Close(rootFD)

	if err := unix.Fsync(rootFD); err != nil {
		return nil, fmt.Errorf("sync storage directory: %w", err)
	}

	return result, nil
}

func writePreparedFile(ctx context.Context, dirFD int, input InputFile) (InstalledFile, error) {
	item := InstalledFile{Name: input.Name}
	fd, err := unix.Openat2(dirFD, input.Name, &unix.OpenHow{
		Flags:   unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Mode:    0600,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV,
	})

	if err != nil {
		return item, fmt.Errorf("create staged media: %w", err)
	}

	file := os.NewFile(uintptr(fd), "staged-media")

	if file == nil {
		_ = unix.Close(fd)
		return item, errors.New("invalid staging file")
	}

	defer file.Close()
	hash := sha256.New()
	item.Size, err = io.Copy(io.MultiWriter(file, hash), &contextReader{ctx: ctx, source: io.LimitReader(input.Reader, input.MaxBytes+1)})

	if err != nil {
		return item, fmt.Errorf("write media: %w", err)
	}

	if item.Size > input.MaxBytes {
		return item, ErrFileTooLarge
	}

	if err := ctx.Err(); err != nil {
		return item, err
	}

	if err := file.Sync(); err != nil {
		return item, fmt.Errorf("sync media: %w", err)
	}

	if err := file.Close(); err != nil {
		return item, fmt.Errorf("close media: %w", err)
	}

	copy(item.SHA256[:], hash.Sum(nil))
	return item, nil
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
