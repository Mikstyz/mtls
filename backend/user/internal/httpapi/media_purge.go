package httpapi

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	"mtls/user/internal/repositories"
)

func (h *Handler) nextMediaPurge(w http.ResponseWriter, r *http.Request) {
	owner, err := h.users.NextMediaPurge(r.Context())
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	if owner == uuid.Nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	w.Header().Set("X-Media-Owner", owner.String())
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) finishMediaPurge(w http.ResponseWriter, r *http.Request) {
	owner, err := uuid.Parse(r.PathValue("owner"))
	if err != nil || owner == uuid.Nil {
		http.Error(w, "invalid owner", http.StatusBadRequest)
		return
	}

	err = h.users.FinishMediaPurge(r.Context(), owner)
	if errors.Is(err, repositories.ErrMediaConflict) {
		http.Error(w, "media policies still active", http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
