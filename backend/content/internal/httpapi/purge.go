package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"mtls/content/internal/catalog"
)

func (h *Handler) purgeAuthor(w http.ResponseWriter, r *http.Request) {
	if !h.authorizedPurge(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	author, err := uuid.Parse(r.PathValue("id"))

	if err != nil || author == uuid.Nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	err = h.purger.PurgeAuthor(ctx, author)
	if errors.Is(err, catalog.ErrCleanupInProgress) {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
