package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"mtls/content/internal/catalog"
)

func (h *Handler) report(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if h.user == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil || id == uuid.Nil {
		http.NotFound(w, r)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	sessionPath := "/api/users/me/participation"
	if r.Method != http.MethodPut {
		sessionPath = "/api/users/me"
	}
	viewer, err := h.user.sessionUser(ctx, r, sessionPath)
	if err != nil {
		writeContentError(w, r, err)
		return
	}

	if r.Method != http.MethodPut {
		report, err := h.catalog.OwnReport(ctx, viewer, id)
		if err != nil {
			writeContentError(w, r, err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(report)
		return
	}

	var input struct {
		PostID    uuid.UUID  `json:"post_id"`
		CommentID *uuid.UUID `json:"comment_id"`
		Reason    string     `json:"reason"`
	}
	if _, ok := readPostCommand(w, r, &input); !ok {
		return
	}

	if input.PostID == uuid.Nil || input.CommentID != nil && *input.CommentID == uuid.Nil {
		http.Error(w, "invalid report target", http.StatusBadRequest)
		return
	}
	switch input.Reason {
	case "spam", "harassment", "consent", "age_safety", "other":
	default:
		http.Error(w, "invalid report reason", http.StatusBadRequest)
		return
	}

	_, err = h.catalog.OwnReport(ctx, viewer, id)
	if err != nil && !errors.Is(err, catalog.ErrPostNotFound) {
		writeContentError(w, r, err)
		return
	}
	if errors.Is(err, catalog.ErrPostNotFound) {
		author, err := h.catalog.ViewablePostAuthor(ctx, viewer, input.PostID)
		if err != nil {
			writeContentError(w, r, err)
			return
		}
		if err := h.user.checkAuthorAccess(ctx, r, author); err != nil {
			writeContentError(w, r, err)
			return
		}

		if input.CommentID != nil {
			commentAuthor, err := h.catalog.ReportCommentAuthor(ctx, input.PostID, *input.CommentID)
			if err != nil {
				writeContentError(w, r, err)
				return
			}
			if commentAuthor != author {
				if err := h.user.checkAuthorAccess(ctx, r, commentAuthor); err != nil {
					writeContentError(w, r, err)
					return
				}
			}
		}
	}

	report := catalog.Report{ID: id, PostID: input.PostID, CommentID: input.CommentID, Reason: input.Reason}
	result, err := h.catalog.SubmitReport(ctx, viewer, report)
	if err != nil {
		writeContentError(w, r, err)
		return
	}
	switch result {
	case "created":
		w.WriteHeader(http.StatusCreated)
	case "replay":
		w.WriteHeader(http.StatusNoContent)
	case "missing":
		http.NotFound(w, r)
	case "conflict":
		http.Error(w, "report already exists", http.StatusConflict)
	case "limited":
		w.Header().Set("Retry-After", "3600")
		http.Error(w, "report limit reached", http.StatusTooManyRequests)
	default:
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}
}
