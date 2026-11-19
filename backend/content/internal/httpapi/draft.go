package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/google/uuid"
	"mtls/content/internal/catalog"
)

func (h *Handler) createDraft(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if h.user == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))

	if err != nil || mediaType != "application/json" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	var input struct {
		RequestID   uuid.UUID `json:"request_id"`
		Kind        string    `json:"kind"`
		Title       string    `json:"title"`
		Description string    `json:"description"`
	}

	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&input); err != nil {
		var tooLarge *http.MaxBytesError

		if errors.As(err, &tooLarge) {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}

		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if err := decoder.Decode(new(any)); err != io.EOF {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	author, err := h.user.author(ctx, r)

	if errors.Is(err, errUnauthorized) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	id, err := h.catalog.CreateDraft(ctx, catalog.Draft{
		AuthorID:    author,
		RequestID:   input.RequestID,
		Kind:        input.Kind,
		Title:       input.Title,
		Description: input.Description,
	})

	if errors.Is(err, catalog.ErrInvalidDraft) {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if errors.Is(err, catalog.ErrAuthorPurging) {
		http.NotFound(w, r)
		return
	}

	if errors.Is(err, catalog.ErrDraftConflict) {
		http.Error(w, "conflict", http.StatusConflict)
		return
	}

	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		ID     uuid.UUID `json:"id"`
		Status string    `json:"status"`
	}{ID: id, Status: "draft"})
}
