// Package authupload ties private upload reservations to a verified user session.
package authupload

import (
	"context"
	"io"

	"github.com/google/uuid"
	"mtls/media-processing/internal/lifecycle"
	"mtls/media-processing/internal/quarantine"
	"mtls/media-processing/internal/userclient"
)

type Service struct {
	ledger *lifecycle.Store
	files  *quarantine.Store
	users  *userclient.Client
	quota  lifecycle.Quota
}

func New(ctx context.Context, ledger *lifecycle.Store, files *quarantine.Store, users *userclient.Client, quota lifecycle.Quota) (*Service, error) {
	if ctx == nil || ledger == nil || files == nil || users == nil {
		return nil, userclient.ErrInvalid
	}

	if err := ledger.ValidateQuotaRole(ctx); err != nil {
		return nil, err
	}

	if err := ledger.ConfigureQuota(ctx, quota); err != nil {
		return nil, err
	}

	return &Service{ledger: ledger, files: files, users: users, quota: quota}, nil
}

// Reserve binds an idempotency key and the original file metadata to the session owner.
func (s *Service) Reserve(ctx context.Context, token string, request uuid.UUID, kind string, size int64, digest [32]byte) (lifecycle.Asset, error) {
	if ctx == nil || s.ledger == nil || s.files == nil || s.users == nil {
		return lifecycle.Asset{}, userclient.ErrInvalid
	}

	owner, err := s.users.Identity(ctx, token)

	if err != nil {
		return lifecycle.Asset{}, err
	}

	asset, err := s.ledger.ReserveUpload(ctx, owner, request, kind, size, digest, s.quota)

	if err != nil {
		return lifecycle.Asset{}, err
	}

	if err := s.users.Reserve(ctx, token, owner, asset.ID); err != nil {
		return lifecycle.Asset{}, err
	}

	return asset, nil
}

// Receive checks the live session and ownership before reading and before publishing.
func (s *Service) Receive(ctx context.Context, token string, media uuid.UUID, size int64, digest [32]byte, source io.Reader) error {
	if ctx == nil || s.ledger == nil || s.files == nil || s.users == nil {
		return userclient.ErrInvalid
	}

	owner, err := s.users.Identity(ctx, token)

	if err != nil {
		return err
	}

	completed, err := s.ledger.UploadComplete(ctx, owner, media, size, digest)
	if err != nil {
		return err
	}

	if completed {
		return nil
	}

	guard := func(ctx context.Context) error {
		if err := s.ledger.CheckUpload(ctx, owner, media, size, digest); err != nil {
			return err
		}

		return s.users.Reserve(ctx, token, owner, media)
	}

	commit := func(ctx context.Context) error {
		return s.ledger.MarkUploaded(ctx, owner, media, size, digest)
	}

	return s.files.Accept(ctx, media, size, digest, source, guard, commit)
}

// Status returns the progress of an upload belonging to the current session.
func (s *Service) Status(ctx context.Context, token string, media uuid.UUID) (string, error) {
	owner, err := s.users.Identity(ctx, token)
	if err != nil {
		return "", err
	}

	return s.ledger.UploadStatus(ctx, owner, media)
}

// Delete records a deletion for the upload owner. The queue revokes access
// before removing files.
func (s *Service) Delete(ctx context.Context, token string, media uuid.UUID) error {
	owner, err := s.users.Identity(ctx, token)
	if err != nil {
		return err
	}

	return s.ledger.BeginDelete(ctx, owner, media)
}
