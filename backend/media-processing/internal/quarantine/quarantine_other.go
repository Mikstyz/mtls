//go:build !linux

// Package quarantine stores private uploads before validation and processing.
package quarantine

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/google/uuid"
)

var (
	ErrInvalid  = errors.New("invalid quarantine operation")
	ErrMismatch = errors.New("upload size or digest mismatch")
	ErrBusy     = errors.New("quarantine is busy")
)

type Store struct{}

func Open(string) (*Store, error) {
	return nil, errors.New("quarantine requires Linux")
}

func (*Store) Accept(context.Context, uuid.UUID, int64, [32]byte, io.Reader, func(context.Context) error, func(context.Context) error) error {
	return errors.New("quarantine requires Linux")
}

func (*Store) Append(context.Context, uuid.UUID, Chunk, io.Reader, func(context.Context) error, func(context.Context) error) (int64, error) {
	return 0, errors.New("quarantine requires Linux")
}

func (*Store) UploadOffset(uuid.UUID) (int64, error) {
	return 0, errors.New("quarantine requires Linux")
}

func (*Store) Read(uuid.UUID) (*os.File, error) {
	return nil, errors.New("quarantine requires Linux")
}

func (*Store) Remove(context.Context, uuid.UUID, func(context.Context) error) error {
	return errors.New("quarantine requires Linux")
}

func (*Store) CleanPartials(context.Context, int) (int, error) {
	return 0, errors.New("quarantine requires Linux")
}

func (*Store) Close() error {
	return nil
}
