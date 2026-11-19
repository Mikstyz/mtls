package securityevents

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"
)

type Publisher interface {
	Publish(context.Context, Event) error
}

type Relay struct {
	store     *Store
	publisher Publisher
}

func NewRelay(store *Store, publisher Publisher) *Relay {
	return &Relay{store: store, publisher: publisher}
}

// ProcessOnce acknowledges a lease only after the broker confirms delivery.
// A crash after delivery and before acknowledgement can produce duplicates.
func (r *Relay) ProcessOnce(ctx context.Context) error {
	claimCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	event, err := r.store.Claim(claimCtx)
	cancel()

	if err != nil {
		return err
	}

	publishCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	err = r.publisher.Publish(publishCtx, event)
	cancel()

	if err != nil {
		if ctx.Err() == nil {
			retryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			retryErr := r.store.Retry(retryCtx, event)
			cancel()

			if retryErr != nil {
				return fmt.Errorf("schedule security event retry: %w", retryErr)
			}
		}

		return errors.New("security event delivery failed")
	}

	completeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return r.store.Complete(completeCtx, event)
}

func (r *Relay) Run(ctx context.Context) {
	for ctx.Err() == nil {
		err := r.ProcessOnce(ctx)

		if err == nil {
			continue
		}

		if ctx.Err() != nil {
			return
		}

		if !errors.Is(err, sql.ErrNoRows) {
			log.Print("security event relay unavailable; will retry")
		}

		timer := time.NewTimer(time.Second)

		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
