// Package deletion coordinates local cleanup while retaining the durable asset record.
package deletion

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"mtls/media-processing/internal/lifecycle"
	"mtls/media-processing/internal/quarantine"
	"mtls/media-processing/internal/storage"
)

type Policy interface {
	Revoke(context.Context, uuid.UUID, uuid.UUID) error
}

type Service struct {
	policy   Policy
	ledger   *lifecycle.Store
	private  *quarantine.Store
	prepared *storage.Store
}

func New(ledger *lifecycle.Store, private *quarantine.Store, prepared *storage.Store, policy Policy) *Service {
	return &Service{ledger: ledger, private: private, prepared: prepared, policy: policy}
}

// Clean retries access revocation and physical removal for an accepted deletion.
func (s *Service) Clean(ctx context.Context, owner, id uuid.UUID) error {
	if ctx == nil || s.policy == nil {
		return lifecycle.ErrInvalid
	}

	if err := s.ledger.CheckDeleting(ctx, owner, id); err != nil {
		return err
	}

	if err := s.policy.Revoke(ctx, owner, id); err != nil {
		return fmt.Errorf("revoke media policy: %w", err)
	}

	guard := func(ctx context.Context) error {
		return s.ledger.CheckDeleting(ctx, owner, id)
	}

	if err := s.private.Remove(ctx, id, guard); err != nil {
		return fmt.Errorf("remove quarantined upload: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	if err := s.ledger.CheckDeleting(ctx, owner, id); err != nil {
		return err
	}

	if err := s.prepared.Delete(id); err != nil {
		return fmt.Errorf("remove prepared media: %w", err)
	}

	return s.ledger.FinishDeletion(ctx, owner, id)
}
