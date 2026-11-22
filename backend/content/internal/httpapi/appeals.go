package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"mtls/content/internal/catalog"
)

func (h *Handler) appeals(w http.ResponseWriter, r *http.Request) {
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

	moderator := strings.HasPrefix(r.URL.Path, "/internal/moderation/")
	sessionPath := "/api/users/me"
	if moderator {
		sessionPath = "/api/users/me/moderator"
	}
	actor, err := h.user.sessionUser(ctx, r, sessionPath)
	if err != nil {
		writeContentError(w, r, err)
		return
	}

	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		if moderator && r.PathValue("id") != "" {
			id, err := uuid.Parse(r.PathValue("id"))
			if err != nil || id == uuid.Nil {
				http.NotFound(w, r)
				return
			}

			detail, err := h.catalog.AppealDetail(ctx, actor, id)
			if err != nil {
				writeContentError(w, r, err)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "private, no-store")
			_ = json.NewEncoder(w).Encode(detail)
			return
		}

		var result any
		if moderator {
			items, err := h.catalog.AppealQueue(ctx, actor)
			if err != nil {
				writeContentError(w, r, err)
				return
			}
			result = struct {
				Appeals []catalog.PendingAppeal `json:"appeals"`
			}{items}
		} else {
			items, err := h.catalog.ModerationNotices(ctx, actor)
			if err != nil {
				writeContentError(w, r, err)
				return
			}
			result = struct {
				Notices []catalog.ModerationNotice `json:"notices"`
			}{items}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
		return
	}

	var status int
	if moderator {
		var input struct {
			Outcome string `json:"outcome"`
		}
		id, ok := readPostCommand(w, r, &input)
		if !ok {
			return
		}
		if input.Outcome != "upheld" && input.Outcome != "reversed" {
			http.Error(w, "invalid appeal outcome", http.StatusBadRequest)
			return
		}
		status, err = h.catalog.ReviewAppeal(ctx, actor, id, input.Outcome)
	} else {
		var input struct {
			Statement string `json:"statement"`
		}
		id, ok := readPostCommandLimit(w, r, &input, 8192)
		if !ok {
			return
		}
		if strings.TrimSpace(input.Statement) == "" || strings.ContainsRune(input.Statement, 0) || utf8.RuneCountInString(input.Statement) > 1000 {
			http.Error(w, "invalid appeal statement", http.StatusBadRequest)
			return
		}
		status, err = h.catalog.SubmitAppeal(ctx, actor, id, input.Statement)
	}
	if err != nil {
		writeContentError(w, r, err)
		return
	}
	switch status {
	case http.StatusCreated, http.StatusNoContent, http.StatusNotFound, http.StatusConflict:
		w.WriteHeader(status)
	default:
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}
}
