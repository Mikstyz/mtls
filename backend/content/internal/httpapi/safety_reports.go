package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
)

func (h *Handler) anonymousSafetyReport(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Cache-Control", "no-store")

	var input struct {
		PostID uuid.UUID `json:"post_id"`
		Reason string    `json:"reason"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF ||
		input.PostID == uuid.Nil || (input.Reason != "consent" && input.Reason != "age_safety") {
		http.Error(w, "invalid safety report", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	accepted, err := h.catalog.SubmitAnonymousSafetyReport(ctx, input.PostID, input.Reason)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if !accepted {
		w.Header().Set("Retry-After", "3600")
		http.Error(w, "safety intake temporarily full", http.StatusTooManyRequests)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}
