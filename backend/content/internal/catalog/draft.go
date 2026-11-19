package catalog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

var (
	ErrInvalidDraft  = errors.New("invalid draft")
	ErrDraftConflict = errors.New("draft request conflicts with prior request")
	ErrAuthorPurging = errors.New("author content is being purged")
)

func validDraftText(title, description string) bool {
	return utf8.ValidString(title) && utf8.ValidString(description) &&
		utf8.RuneCountInString(title) <= 200 && utf8.RuneCountInString(description) <= 4096 &&
		!strings.ContainsRune(title, 0) && !strings.ContainsRune(description, 0)
}

type Draft struct {
	AuthorID    uuid.UUID
	RequestID   uuid.UUID
	Kind        string
	Title       string
	Description string
}

// CreateDraft uses a per-author request ID to make retries safe.
func (s *Store) CreateDraft(ctx context.Context, draft Draft) (uuid.UUID, error) {
	if draft.AuthorID == uuid.Nil || draft.RequestID == uuid.Nil || (draft.Kind != "photo" && draft.Kind != "video") {
		return uuid.Nil, ErrInvalidDraft
	}

	if !validDraftText(draft.Title, draft.Description) {
		return uuid.Nil, ErrInvalidDraft
	}

	tx, err := s.db.BeginTx(ctx, nil)

	if err != nil {
		return uuid.Nil, fmt.Errorf("begin draft creation: %w", err)
	}

	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "content-author:"+draft.AuthorID.String()); err != nil {
		return uuid.Nil, fmt.Errorf("lock draft author: %w", err)
	}

	var purging bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM content_author_purges WHERE author_id=$1)`, draft.AuthorID).Scan(&purging); err != nil {
		return uuid.Nil, fmt.Errorf("check author cleanup: %w", err)
	}

	if purging {
		return uuid.Nil, ErrAuthorPurging
	}

	key := draft.AuthorID.String() + ":" + draft.RequestID.String()

	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, key); err != nil {
		return uuid.Nil, fmt.Errorf("lock draft request: %w", err)
	}

	var existing uuid.UUID
	var kind, title, description string
	err = tx.QueryRowContext(ctx, `SELECT post_id, media_kind, title, description FROM content_draft_requests WHERE author_id=$1 AND request_id=$2`, draft.AuthorID, draft.RequestID).Scan(&existing, &kind, &title, &description)

	if err == nil {
		if kind != draft.Kind || title != draft.Title || description != draft.Description {
			return uuid.Nil, ErrDraftConflict
		}

		if err := tx.Commit(); err != nil {
			return uuid.Nil, fmt.Errorf("commit draft replay: %w", err)
		}

		return existing, nil
	}

	if !errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, fmt.Errorf("lookup draft request: %w", err)
	}

	id, err := uuid.NewRandom()

	if err != nil {
		return uuid.Nil, fmt.Errorf("generate draft id: %w", err)
	}

	_, err = tx.ExecContext(ctx, `INSERT INTO content_posts(id, author_id, media_kind, title, description) VALUES($1,$2,$3,$4,$5)`, id, draft.AuthorID, draft.Kind, draft.Title, draft.Description)

	if err != nil {
		return uuid.Nil, fmt.Errorf("create draft: %w", err)
	}

	_, err = tx.ExecContext(ctx, `INSERT INTO content_draft_requests(author_id, request_id, post_id, media_kind, title, description) VALUES($1,$2,$3,$4,$5,$6)`, draft.AuthorID, draft.RequestID, id, draft.Kind, draft.Title, draft.Description)

	if err != nil {
		return uuid.Nil, fmt.Errorf("record draft request: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return uuid.Nil, fmt.Errorf("commit draft creation: %w", err)
	}

	return id, nil
}
