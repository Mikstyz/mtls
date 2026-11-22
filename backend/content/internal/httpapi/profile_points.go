package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
)

func authorizedDelivery(r *http.Request, key string) bool {
	secrets := r.Header.Values("X-Internal-Secret")
	return key != "" && len(secrets) == 1 &&
		subtle.ConstantTimeCompare([]byte(secrets[0]), []byte(key)) == 1
}

func (h *Handler) profilePointsEvent(w http.ResponseWriter, r *http.Request) {
	if !authorizedDelivery(r, h.deliverySecrets.ProfilePoints) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var input struct {
		CaseID    uuid.UUID `json:"case_id"`
		OwnerID   uuid.UUID `json:"owner_id"`
		Operation string    `json:"operation"`
		Reason    string    `json:"reason"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF ||
		input.CaseID == uuid.Nil || input.OwnerID == uuid.Nil ||
		(input.Operation != "deduct" && input.Operation != "reverse") || input.Reason == "" {
		http.Error(w, "invalid profile moderation event", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	accepted, err := h.catalog.ApplyProfilePointsEvent(ctx, input.CaseID, input.OwnerID, input.Operation, input.Reason)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if !accepted {
		http.Error(w, "profile moderation event conflict", http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
