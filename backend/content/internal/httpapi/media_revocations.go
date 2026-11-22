package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
)

func (h *Handler) mediaRevocation(w http.ResponseWriter, r *http.Request) {
	if !authorizedDelivery(r, h.deliverySecrets.MediaRevocation) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var input struct {
		MediaID uuid.UUID `json:"media_id"`
		OwnerID uuid.UUID `json:"owner_id"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF ||
		input.MediaID == uuid.Nil || input.OwnerID == uuid.Nil {
		http.Error(w, "invalid media revocation", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	accepted, err := h.catalog.RevokeMediaAttachment(ctx, input.OwnerID, input.MediaID)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if !accepted {
		http.Error(w, "media revocation conflict", http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
