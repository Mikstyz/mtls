package securityevents

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/google/uuid"
)

var ErrJournalGap = errors.New("security journal offset gap")
var ErrJournalConflict = errors.New("security journal event conflict")
var ErrInvalidEvent = errors.New("invalid security event")

type Journal struct {
	db *sql.DB
}

func NewJournal(db *sql.DB) *Journal {
	return &Journal{db: db}
}

// CheckVersions detects internal per-user gaps in archived events. It cannot
// prove that the newest event was delivered or that the source was complete.
func (j *Journal) CheckVersions(ctx context.Context) error {
	var gaps bool

	if err := j.db.QueryRowContext(ctx, `SELECT EXISTS (
		SELECT 1 FROM security_journal_events GROUP BY user_id
		HAVING min(version) <> 1 OR count(*) <> max(version)
	)`).Scan(&gaps); err != nil {
		return fmt.Errorf("check journal versions: %w", err)
	}

	if gaps {
		return ErrJournalGap
	}

	return nil
}

// Initialize binds a new journal to a topic ID and its complete partition set.
// Existing journals reject topic replacement or partition changes.
func (j *Journal) Initialize(ctx context.Context, topic string, topicID uuid.UUID, partitions []int32) (map[int32]int64, error) {
	if !topicPattern.MatchString(topic) || topicID == uuid.Nil || len(partitions) == 0 || len(partitions) > 64 {
		return nil, ErrInvalidEvent
	}

	expected := make(map[int32]bool, len(partitions))

	for _, partition := range partitions {
		if partition < 0 || expected[partition] {
			return nil, ErrInvalidEvent
		}

		expected[partition] = true
	}

	tx, err := j.db.BeginTx(ctx, nil)

	if err != nil {
		return nil, fmt.Errorf("begin journal initialization: %w", err)
	}

	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "security-journal:"+topic); err != nil {
		return nil, fmt.Errorf("lock journal initialization: %w", err)
	}

	rows, err := tx.QueryContext(ctx, `SELECT topic_id, partition, next_offset FROM security_journal_offsets
		WHERE topic = $1 FOR UPDATE`, topic)

	if err != nil {
		return nil, fmt.Errorf("read journal offsets: %w", err)
	}

	offsets := make(map[int32]int64, len(partitions))

	for rows.Next() {
		var storedTopic uuid.UUID
		var partition int32
		var offset int64

		if err := rows.Scan(&storedTopic, &partition, &offset); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan journal offset: %w", err)
		}

		if storedTopic != topicID || !expected[partition] {
			rows.Close()
			return nil, ErrJournalConflict
		}

		offsets[partition] = offset
	}

	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("iterate journal offsets: %w", err)
	}

	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close journal offsets: %w", err)
	}

	if len(offsets) != 0 && len(offsets) != len(expected) {
		return nil, ErrJournalConflict
	}

	if len(offsets) == 0 {
		for _, partition := range partitions {
			if _, err := tx.ExecContext(ctx, `INSERT INTO security_journal_offsets (topic, topic_id, partition, next_offset)
				VALUES ($1, $2, $3, 0)`, topic, topicID, partition); err != nil {
				return nil, fmt.Errorf("initialize journal offset: %w", err)
			}

			offsets[partition] = 0
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit journal initialization: %w", err)
	}

	return offsets, nil
}

// Archive stores an event and advances its partition offset in one transaction.
// Any gap, topic replacement or conflicting event leaves the offset unchanged.
func (j *Journal) Archive(ctx context.Context, topic string, topicID uuid.UUID, partition int32, offset int64, key, payload []byte) error {
	if !topicPattern.MatchString(topic) || topicID == uuid.Nil || partition < 0 || offset < 0 || len(payload) == 0 || len(payload) > 4096 {
		return ErrInvalidEvent
	}

	var record struct {
		SchemaVersion int `json:"schema_version"`
		Event
	}

	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&record); err != nil {
		return ErrInvalidEvent
	}

	if err := decoder.Decode(new(any)); err != io.EOF {
		return ErrInvalidEvent
	}

	if record.SchemaVersion != 1 || record.ID == uuid.Nil || record.UserID == uuid.Nil ||
		record.Version < 1 || record.CreatedAt.IsZero() || string(key) != record.UserID.String() ||
		!validJournalEvent(record.Event) {
		return ErrInvalidEvent
	}

	tx, err := j.db.BeginTx(ctx, nil)

	if err != nil {
		return fmt.Errorf("begin journal append: %w", err)
	}

	defer tx.Rollback()

	var storedTopicID uuid.UUID
	var next int64
	err = tx.QueryRowContext(ctx, `SELECT topic_id, next_offset FROM security_journal_offsets
		WHERE topic = $1 AND partition = $2 FOR UPDATE`, topic, partition).Scan(&storedTopicID, &next)

	if errors.Is(err, sql.ErrNoRows) {
		return ErrJournalConflict
	}

	if err != nil {
		return fmt.Errorf("lock journal offset: %w", err)
	}

	if storedTopicID != topicID {
		return ErrJournalConflict
	}

	if offset > next {
		return ErrJournalGap
	}

	if offset < next {
		var previousID uuid.UUID
		var previousPayload []byte
		err := tx.QueryRowContext(ctx, `SELECT d.event_id, e.payload FROM security_journal_deliveries d
			JOIN security_journal_events e ON e.event_id = d.event_id
			WHERE d.topic = $1 AND d.partition = $2 AND d.offset_value = $3`, topic, partition, offset).Scan(&previousID, &previousPayload)

		if errors.Is(err, sql.ErrNoRows) || (err == nil && (previousID != record.ID || !bytes.Equal(previousPayload, payload))) {
			return ErrJournalConflict
		}

		if err != nil {
			return fmt.Errorf("check previous journal delivery: %w", err)
		}

		return tx.Commit()
	}

	result, err := tx.ExecContext(ctx, `INSERT INTO security_journal_events (event_id, user_id, version, event_type, payload)
		VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`, record.ID, record.UserID, record.Version, record.Type, payload)

	if err != nil {
		return fmt.Errorf("store security event: %w", err)
	}

	count, err := result.RowsAffected()

	if err != nil {
		return fmt.Errorf("check security event insert: %w", err)
	}

	if count == 0 {
		var existing []byte
		err := tx.QueryRowContext(ctx, `SELECT payload FROM security_journal_events WHERE event_id = $1`, record.ID).Scan(&existing)

		if errors.Is(err, sql.ErrNoRows) || (err == nil && !bytes.Equal(existing, payload)) {
			return ErrJournalConflict
		}

		if err != nil {
			return fmt.Errorf("check duplicate security event: %w", err)
		}
	}

	if _, err := tx.ExecContext(ctx, `INSERT INTO security_journal_deliveries (topic, partition, offset_value, event_id)
		VALUES ($1, $2, $3, $4)`, topic, partition, offset, record.ID); err != nil {
		return fmt.Errorf("record journal delivery: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `UPDATE security_journal_offsets SET next_offset = $3
		WHERE topic = $1 AND partition = $2`, topic, partition, offset+1); err != nil {
		return fmt.Errorf("advance journal offset: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit journal event: %w", err)
	}

	return nil
}

func validJournalEvent(event Event) bool {
	switch event.Type {
	case "password_changed", "credentials_enabled", "credentials_disabled", "credentials_deleted", "session_revoked", "role_changed":
		return event.LifecycleState == nil && event.DeletedAt == nil
	case "deletion_started", "account_archived", "restore_started", "purge_started", "account_restored", "account_purged", "deletion_record_removed":
		if event.LifecycleState == nil || event.DeletedAt == nil || event.DeletedAt.IsZero() {
			return false
		}

		switch event.Type {
		case "deletion_started":
			return *event.LifecycleState == "deleting"
		case "account_archived":
			return *event.LifecycleState == "deleted"
		case "restore_started", "account_restored":
			return *event.LifecycleState == "restoring_owner" || *event.LifecycleState == "restoring_moderator"
		case "purge_started", "account_purged":
			return *event.LifecycleState == "purging"
		case "deletion_record_removed":
			return *event.LifecycleState == "deleting" || *event.LifecycleState == "deleted" ||
				*event.LifecycleState == "restoring_owner" || *event.LifecycleState == "restoring_moderator"
		}
	}

	return false
}
