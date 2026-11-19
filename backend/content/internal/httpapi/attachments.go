package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"mime"
	"net/http"
	"time"

	"github.com/google/uuid"
)

func (h *Handler) setDraftMedia(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if h.user == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	id, err := uuid.Parse(r.PathValue("id"))
	mediaType, _, mediaErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || id == uuid.Nil || mediaErr != nil || mediaType != "application/json" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	var input struct {
		Revision int64       `json:"revision"`
		Media    []uuid.UUID `json:"media_ids"`
	}

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF ||
		input.Revision < 1 || input.Revision == math.MaxInt64 || input.Media == nil || len(input.Media) > 16 {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	seen := make(map[uuid.UUID]bool, len(input.Media))
	for _, media := range input.Media {
		if media == uuid.Nil || seen[media] {
			http.Error(w, "invalid media list", http.StatusBadRequest)
			return
		}
		seen[media] = true
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	author, err := h.user.author(ctx, r)
	if err != nil {
		writeContentError(w, r, err)
		return
	}

	for _, media := range input.Media {
		if err := h.user.checkMediaOwner(ctx, r, media); err != nil {
			writeContentError(w, r, err)
			return
		}
	}

	revision, err := h.catalog.SetDraftMedia(ctx, author, id, input.Revision, input.Media)
	if err != nil {
		writeContentError(w, r, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Revision int64 `json:"revision"`
	}{Revision: revision})
}
