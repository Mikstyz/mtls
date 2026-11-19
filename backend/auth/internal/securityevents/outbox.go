package securityevents

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

var ErrLeaseLost = errors.New("security event lease no longer valid")

type Event struct {
	ID             uuid.UUID  `json:"event_id"`
	UserID         uuid.UUID  `json:"user_id"`
	Version        int64      `json:"version"`
	Type           string     `json:"type"`
	LifecycleState *string    `json:"lifecycle_state,omitempty"`
	DeletedAt      *time.Time `json:"deleted_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	LeaseID        uuid.UUID  `json:"-"`
}

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// Claim leases the oldest unpublished event of one account, preventing a
// later event from passing an unpublished predecessor in the database.
func (s *Store) Claim(ctx context.Context) (Event, error) {
	leaseID, err := uuid.NewRandom()

	if err != nil {
		return Event{}, fmt.Errorf("generate security event lease: %w", err)
	}

	const query = `WITH selected AS (
		SELECT e.event_id FROM security_event_outbox e
		WHERE e.published_at IS NULL AND e.available_at <= clock_timestamp()
			AND (e.lease_until IS NULL OR e.lease_until <= clock_timestamp())
			AND NOT EXISTS (SELECT 1 FROM security_event_outbox previous
				WHERE previous.user_id = e.user_id AND previous.version < e.version
					AND previous.published_at IS NULL)
		ORDER BY e.available_at, e.created_at, e.event_id
		LIMIT 1 FOR UPDATE OF e SKIP LOCKED
	)
	UPDATE security_event_outbox e SET lease_id = $1,
		lease_until = clock_timestamp() + INTERVAL '2 minutes', attempts = attempts + 1
	FROM selected WHERE e.event_id = selected.event_id
	RETURNING e.event_id, e.user_id, e.version, e.event_type,
		e.lifecycle_state, e.deleted_at, e.created_at`

	var event Event
	var state sql.NullString
	var deletedAt sql.NullTime
	err = s.db.QueryRowContext(ctx, query, leaseID).Scan(
		&event.ID, &event.UserID, &event.Version, &event.Type,
		&state, &deletedAt, &event.CreatedAt,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return Event{}, sql.ErrNoRows
	}

	if err != nil {
		return Event{}, fmt.Errorf("claim security event: %w", err)
	}

	if state.Valid {
		event.LifecycleState = &state.String
	}

	if deletedAt.Valid {
		event.DeletedAt = &deletedAt.Time
	}

	event.LeaseID = leaseID
	return event, nil
}

func (s *Store) Complete(ctx context.Context, event Event) error {
	const query = `UPDATE security_event_outbox SET published_at = clock_timestamp(),
		lease_id = NULL, lease_until = NULL
		WHERE event_id = $1 AND lease_id = $2 AND published_at IS NULL`

	return s.updateLease(ctx, query, event)
}

func (s *Store) Retry(ctx context.Context, event Event) error {
	const query = `UPDATE security_event_outbox SET lease_id = NULL, lease_until = NULL,
		available_at = clock_timestamp() +
			(LEAST(3600, 10 * power(2, LEAST(attempts, 8)) * (0.8 + random() * 0.4)) * INTERVAL '1 second')
		WHERE event_id = $1 AND lease_id = $2 AND published_at IS NULL`

	return s.updateLease(ctx, query, event)
}

func (s *Store) updateLease(ctx context.Context, query string, event Event) error {
	result, err := s.db.ExecContext(ctx, query, event.ID, event.LeaseID)

	if err != nil {
		return fmt.Errorf("update security event lease: %w", err)
	}

	count, err := result.RowsAffected()

	if err != nil {
		return fmt.Errorf("check security event lease: %w", err)
	}

	if count != 1 {
		return ErrLeaseLost
	}

	return nil
}
