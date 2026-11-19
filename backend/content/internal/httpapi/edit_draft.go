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

func (h *Handler) editDraft(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))

	if err != nil || mediaType != "application/json" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	var input struct {
		Revision    *int64  `json:"revision"`
		Title       *string `json:"title"`
		Description *string `json:"description"`
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

	if input.Revision == nil || input.Title == nil || input.Description == nil || decoder.Decode(new(any)) != io.EOF {
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

	revision, err := h.catalog.EditDraft(ctx, author, id, *input.Revision, *input.Title, *input.Description)

	switch {
	case errors.Is(err, catalog.ErrInvalidDraft):
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	case errors.Is(err, catalog.ErrDraftNotFound):
		http.NotFound(w, r)
		return
	case errors.Is(err, catalog.ErrDraftVersionConflict):
		http.Error(w, "conflict", http.StatusConflict)
		return
	case err != nil:
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Revision int64 `json:"revision"`
	}{Revision: revision})
}
