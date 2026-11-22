package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
)

func (h *Handler) participation(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	owner, err := uuid.Parse(r.PathValue("id"))
	if err != nil || owner == uuid.Nil {
		http.NotFound(w, r)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	banned, err := h.catalog.ParticipationBanned(ctx, owner)
	if err != nil {
		writeContentError(w, r, err)
		return
	}
	if banned {
		http.Error(w, "participation restricted", http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
