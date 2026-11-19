package securityevents

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
)

// RecoveryIssue contains sensitive identifiers; its error text deliberately omits them.
type RecoveryIssue struct {
	UserID    uuid.UUID `json:"user_id"`
	EventID   uuid.UUID `json:"event_id"`
	Version   int64     `json:"version"`
	EventType string    `json:"event_type"`
	Kind      string    `json:"kind"`
	cause     error
}

func (issue *RecoveryIssue) Error() string {
	if issue.cause != nil {
		return issue.cause.Error()
	}

	return "security journal recovery difference"
}

func (issue *RecoveryIssue) Unwrap() error {
	return issue.cause
}

func newRecoveryIssue(event Event, kind string, cause error) *RecoveryIssue {
	return &RecoveryIssue{
		UserID: event.UserID, EventID: event.ID, Version: event.Version,
		EventType: event.Type, Kind: kind, cause: cause,
	}
}

// RecoveryComparison compares the available source snapshot, not changes lost before publication.
type RecoveryComparison struct {
	SourceEvents      int64
	JournalOnlyEvents int64
	FirstJournalOnly  *RecoveryIssue
}

// CompareRecoverySource must be run with auth writes stopped and the journal caught up.
// A matching snapshot does not prove that a lost source contained no later changes.
func CompareRecoverySource(ctx context.Context, source, journal *sql.DB) (RecoveryComparison, error) {
	var result RecoveryComparison

	sourceTx, err := source.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return result, fmt.Errorf("open source snapshot: %w", err)
	}

	defer sourceTx.Rollback()

	journalTx, err := journal.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return result, fmt.Errorf("open journal snapshot: %w", err)
	}

	defer journalTx.Rollback()

	var gaps bool
	if err := sourceTx.QueryRowContext(ctx, `SELECT EXISTS (
		SELECT 1 FROM security_event_versions v LEFT JOIN security_event_outbox e ON e.user_id = v.user_id
		GROUP BY v.user_id, v.version HAVING count(e.event_id) <> v.version OR min(e.version) <> 1 OR max(e.version) <> v.version
	) OR EXISTS (SELECT 1 FROM security_event_outbox e WHERE NOT EXISTS
		(SELECT 1 FROM security_event_versions v WHERE v.user_id = e.user_id))`).Scan(&gaps); err != nil {
		return result, fmt.Errorf("check source versions: %w", err)
	}

	if gaps {
		return result, ErrJournalGap
	}

	if err := journalTx.QueryRowContext(ctx, `SELECT EXISTS (
		SELECT 1 FROM security_journal_events GROUP BY user_id HAVING min(version) <> 1 OR count(*) <> max(version)
	)`).Scan(&gaps); err != nil {
		return result, fmt.Errorf("check journal versions: %w", err)
	}

	if gaps {
		return result, ErrJournalGap
	}

	sourceRows, err := sourceTx.QueryContext(ctx, `SELECT event_id, user_id, version, event_type, lifecycle_state, deleted_at, created_at
		FROM security_event_outbox ORDER BY user_id, version`)
	if err != nil {
		return result, fmt.Errorf("read source events: %w", err)
	}

	defer sourceRows.Close()

	journalRows, err := journalTx.QueryContext(ctx, `SELECT event_id, user_id, version, event_type, payload
		FROM security_journal_events ORDER BY user_id, version`)
	if err != nil {
		return result, fmt.Errorf("read journal events: %w", err)
	}

	defer journalRows.Close()

	var src, archived Event
	moreSource, moreJournal := sourceRows.Next(), journalRows.Next()
	if moreSource {
		if err := scanSourceEvent(sourceRows, &src); err != nil {
			return result, err
		}
	}

	if moreJournal {
		if err := scanJournalEvent(journalRows, &archived); err != nil {
			return result, err
		}
	}

	for moreSource || moreJournal {
		if err := ctx.Err(); err != nil {
			return result, err
		}

		if !moreJournal || (moreSource && compareEventPosition(src, archived) < 0) {
			return result, newRecoveryIssue(src, "missing_from_journal", ErrJournalGap)
		}

		if !moreSource || compareEventPosition(src, archived) > 0 {
			if result.FirstJournalOnly == nil {
				result.FirstJournalOnly = newRecoveryIssue(archived, "missing_from_source", nil)
			}

			result.JournalOnlyEvents++
			moreJournal = journalRows.Next()
			if moreJournal {
				if err := scanJournalEvent(journalRows, &archived); err != nil {
					return result, err
				}
			}
			continue
		}

		if !sameRecoveryEvent(src, archived) {
			return result, newRecoveryIssue(archived, "event_conflict", ErrJournalConflict)
		}

		result.SourceEvents++
		moreSource, moreJournal = sourceRows.Next(), journalRows.Next()
		if moreSource {
			if err := scanSourceEvent(sourceRows, &src); err != nil {
				return result, err
			}
		}

		if moreJournal {
			if err := scanJournalEvent(journalRows, &archived); err != nil {
				return result, err
			}
		}
	}

	if err := sourceRows.Err(); err != nil {
		return result, fmt.Errorf("iterate source events: %w", err)
	}

	if err := journalRows.Err(); err != nil {
		return result, fmt.Errorf("iterate journal events: %w", err)
	}

	if err := sourceRows.Close(); err != nil {
		return result, err
	}

	if err := journalRows.Close(); err != nil {
		return result, err
	}

	if err := sourceTx.Commit(); err != nil {
		return result, fmt.Errorf("close source snapshot: %w", err)
	}

	if err := journalTx.Commit(); err != nil {
		return result, fmt.Errorf("close journal snapshot: %w", err)
	}

	return result, nil
}

func scanSourceEvent(rows *sql.Rows, event *Event) error {
	var state sql.NullString
	var deleted sql.NullTime
	*event = Event{}
	if err := rows.Scan(&event.ID, &event.UserID, &event.Version, &event.Type, &state, &deleted, &event.CreatedAt); err != nil {
		return fmt.Errorf("scan source event: %w", err)
	}

	if state.Valid {
		event.LifecycleState = &state.String
	}

	if deleted.Valid {
		event.DeletedAt = &deleted.Time
	}

	if event.ID == uuid.Nil || event.UserID == uuid.Nil || event.Version < 1 || event.CreatedAt.IsZero() || !validJournalEvent(*event) {
		return ErrJournalConflict
	}

	return nil
}

func scanJournalEvent(rows *sql.Rows, event *Event) error {
	var id, user uuid.UUID
	var version int64
	var kind string
	var payload []byte
	if err := rows.Scan(&id, &user, &version, &kind, &payload); err != nil {
		return fmt.Errorf("scan journal event: %w", err)
	}

	if len(payload) == 0 || len(payload) > 4096 {
		return ErrJournalConflict
	}
	var record struct {
		SchemaVersion int `json:"schema_version"`
		Event
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&record) != nil || decoder.Decode(new(any)) != io.EOF || record.SchemaVersion != 1 ||
		record.ID != id || record.UserID != user || record.Version != version || record.Type != kind ||
		record.ID == uuid.Nil || record.UserID == uuid.Nil || record.Version < 1 || record.CreatedAt.IsZero() || !validJournalEvent(record.Event) {
		return ErrJournalConflict
	}

	*event = record.Event
	return nil
}

func compareEventPosition(a, b Event) int {
	if n := bytes.Compare(a.UserID[:], b.UserID[:]); n != 0 {
		return n
	}

	if a.Version < b.Version {
		return -1
	}

	if a.Version > b.Version {
		return 1
	}

	return 0
}

func sameRecoveryEvent(a, b Event) bool {
	return a.ID == b.ID && a.UserID == b.UserID && a.Version == b.Version && a.Type == b.Type &&
		a.CreatedAt.Equal(b.CreatedAt) && sameOptionalString(a.LifecycleState, b.LifecycleState) && sameOptionalTime(a.DeletedAt, b.DeletedAt)
}

func sameOptionalString(a, b *string) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}

func sameOptionalTime(a, b *time.Time) bool {
	return a == nil && b == nil || a != nil && b != nil && a.Equal(*b)
}
