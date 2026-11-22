package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"
	"mtls/content/internal/catalog"
)

func (h *Handler) moderate(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if h.user == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	actor, err := h.user.sessionUser(ctx, r, "/api/users/me/moderator")
	if err != nil {
		writeContentError(w, r, err)
		return
	}
	if r.Method != http.MethodPut && r.PathValue("id") != "" {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil || id == uuid.Nil {
			http.NotFound(w, r)
			return
		}

		var before *int64
		if query := r.URL.RawQuery; query != "" {
			params, err := url.ParseQuery(query)
			if len(query) > 128 || err != nil || len(params) != 1 || len(params["before_revision"]) != 1 {
				http.Error(w, "invalid moderation history cursor", http.StatusBadRequest)
				return
			}

			revision, err := strconv.ParseInt(params.Get("before_revision"), 10, 64)
			if err != nil || revision < 1 {
				http.Error(w, "invalid moderation history cursor", http.StatusBadRequest)
				return
			}

			before = &revision
		}

		detail, err := h.catalog.ModerationCaseDetail(ctx, actor, id, before)
		if err != nil {
			writeContentError(w, r, err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(detail)
		return
	}
	if r.Method != http.MethodPut {
		h.listModerationCases(ctx, w, r, actor)
		return
	}

	var action catalog.ModerationAction
	id, ok := readPostCommand(w, r, &action)
	if !ok {
		return
	}
	if !validPostRevision(action.Revision) || action.Request == uuid.Nil || !validModerationAction(action) {
		http.Error(w, "invalid moderation action", http.StatusBadRequest)
		return
	}

	next, err := h.catalog.ModerateReport(ctx, actor, id, action)
	if err != nil {
		writeContentError(w, r, err)
		return
	}
	writePostRevision(w, next)
}

func validModerationAction(action catalog.ModerationAction) bool {
	switch action.Action {
	case "claim", "release", "escalate", "hide", "dismiss":
		return action.Rule == nil && action.Severity == nil
	case "confirm", "remove":
		if action.Rule == nil || action.Severity == nil {
			return false
		}
		switch *action.Rule {
		case "spam", "harassment", "consent", "age_safety", "other":
		default:
			return false
		}
		level := *action.Severity
		return level == "low" || level == "medium" || level == "high" || level == "critical"
	default:
		return false
	}
}

func (h *Handler) listModerationCases(ctx context.Context, w http.ResponseWriter, r *http.Request, actor uuid.UUID) {
	var after *catalog.ModerationQueueCursor
	if query := r.URL.RawQuery; query != "" {
		params, err := url.ParseQuery(query)
		if len(query) > 256 || err != nil || len(params) != 1 || len(params["cursor"]) != 1 {
			http.Error(w, "invalid moderation queue cursor", http.StatusBadRequest)
			return
		}

		data, err := base64.RawURLEncoding.DecodeString(params.Get("cursor"))
		var cursor catalog.ModerationQueueCursor
		if err != nil || json.Unmarshal(data, &cursor) != nil || cursor.CaseID == uuid.Nil || cursor.CreatedAt.IsZero() {
			http.Error(w, "invalid moderation queue cursor", http.StatusBadRequest)
			return
		}

		after = &cursor
	}

	cases, err := h.catalog.ModerationQueue(ctx, actor, after)
	if err != nil {
		writeContentError(w, r, err)
		return
	}

	const pageSize = 50
	var next string
	if len(cases) > pageSize {
		cases = cases[:pageSize]
		last := cases[pageSize-1]
		cursor, err := json.Marshal(catalog.ModerationQueueCursor{
			Escalated: last.Escalated,
			CreatedAt: last.CreatedAt,
			CaseID:    last.ID,
		})
		if err != nil {
			writeContentError(w, r, err)
			return
		}

		next = base64.RawURLEncoding.EncodeToString(cursor)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Cases      []catalog.ModerationCase `json:"cases"`
		NextCursor string                   `json:"next_cursor,omitempty"`
	}{Cases: cases, NextCursor: next})
}
