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

	owner, err := s.users.UploadIdentity(ctx, token)

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

	owner, err := s.users.UploadIdentity(ctx, token)

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

	if err := s.ledger.BeginUpload(ctx, owner, media, size, digest, false); err != nil {
		return err
	}

	guard, commit := s.uploadCallbacks(token, owner, media, size, digest)
	return s.files.Accept(ctx, media, size, digest, source, guard, commit)
}

func (s *Service) ReceiveChunk(ctx context.Context, token string, media uuid.UUID, chunk quarantine.Chunk, source io.Reader) (int64, error) {
	owner, err := s.users.UploadIdentity(ctx, token)
	if err != nil {
		return 0, err
	}

	completed, err := s.ledger.UploadComplete(ctx, owner, media, chunk.Total, chunk.Digest)
	if err != nil {
		return 0, err
	}
	if completed {
		return chunk.Total, nil
	}
	if err := s.ledger.BeginUpload(ctx, owner, media, chunk.Total, chunk.Digest, true); err != nil {
		return 0, err
	}

	guard, commit := s.uploadCallbacks(token, owner, media, chunk.Total, chunk.Digest)
	return s.files.Append(ctx, media, chunk, source, guard, commit)
}

func (s *Service) uploadCallbacks(token string, owner, media uuid.UUID, size int64, digest [32]byte) (func(context.Context) error, func(context.Context) error) {
	guard := func(ctx context.Context) error {
		if err := s.ledger.CheckUpload(ctx, owner, media, size, digest); err != nil {
			return err
		}

		return s.users.Reserve(ctx, token, owner, media)
	}

	commit := func(ctx context.Context) error {
		return s.ledger.MarkUploaded(ctx, owner, media, size, digest)
	}

	return guard, commit
}

// Status returns the progress of an upload belonging to the current session.
func (s *Service) Status(ctx context.Context, token string, media uuid.UUID) (lifecycle.UploadProgress, error) {
	owner, err := s.users.Identity(ctx, token)
	if err != nil {
		return lifecycle.UploadProgress{}, err
	}

	progress, err := s.ledger.UploadStatus(ctx, owner, media)
	if err != nil || !progress.Resumable {
		return progress, err
	}

	offset, err := s.files.UploadOffset(media)
	if err != nil {
		return lifecycle.UploadProgress{}, err
	}

	progress.Offset = &offset
	return progress, nil
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

// History lists uploads owned by the current session.
func (s *Service) History(ctx context.Context, token string, before *lifecycle.UploadPosition) ([]lifecycle.UploadHistoryItem, error) {
	owner, err := s.users.Identity(ctx, token)
	if err != nil {
		return nil, err
	}

	return s.ledger.UploadHistory(ctx, owner, before)
}
