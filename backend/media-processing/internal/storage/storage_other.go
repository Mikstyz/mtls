//go:build !linux

package storage

import (
	"context"
	"errors"
	"io"

	"github.com/google/uuid"
)

type Store struct{}

var ErrStorageBusy = errors.New("media storage is busy")
var ErrFileTooLarge = errors.New("media file exceeds size limit")
var ErrSetMismatch = errors.New("installed media set does not match")

func Open(string) (*Store, error) {
	return nil, errors.New("media cleanup requires Linux")
}

func (*Store) Delete(uuid.UUID) error {
	return errors.New("media cleanup requires Linux")
}

func (*Store) WithWriteLock(func() error) error {
	return errors.New("media cleanup requires Linux")
}

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

func (*Store) InstallSet(context.Context, uuid.UUID, []InputFile) ([]InstalledFile, error) {
	return nil, errors.New("media installation requires Linux")
}

func (*Store) CleanStages(context.Context, int) (int, error) {
	return 0, errors.New("media cleanup requires Linux")
}

func (*Store) VerifySet(context.Context, uuid.UUID, []InstalledFile) error {
	return errors.New("media verification requires Linux")
}

func (*Store) InstallGuarded(context.Context, uuid.UUID, []InputFile, []InstalledFile, func(context.Context) error, func(context.Context) error) error {
	return errors.New("media installation requires Linux")
}

func (*Store) Close() error {
	return nil
}
