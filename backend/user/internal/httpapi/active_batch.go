package httpapi

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
)

func (h *Handler) activeAccountsForViewer(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()

	viewer, ok := h.authenticateParticipant(w, r.WithContext(ctx))
	if !ok {
		return
	}

	if len(r.URL.RawQuery) > 2048 {
		http.Error(w, "invalid accounts", http.StatusBadRequest)
		return
	}

	params, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(params) != 1 || len(params["id"]) == 0 || len(params["id"]) > 40 {
		http.Error(w, "invalid accounts", http.StatusBadRequest)
		return
	}

	ids := []uuid.UUID{viewer.UserID}
	requested := make([]uuid.UUID, 0, len(params["id"]))
	seen := make(map[uuid.UUID]bool, len(params["id"]))

	for _, value := range params["id"] {
		id, err := uuid.Parse(value)
		if err != nil || id == uuid.Nil || seen[id] {
			http.Error(w, "invalid accounts", http.StatusBadRequest)
			return
		}
		seen[id] = true
		requested = append(requested, id)
		if id != viewer.UserID {
			ids = append(ids, id)
		}
	}

	profiles, err := h.users.ExistingProfiles(ctx, ids)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	active, err := h.activeAccounts(ctx, profiles)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if !active[viewer.UserID] {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	visible := requested[:0]
	for _, id := range requested {
		if active[id] {
			visible = append(visible, id)
		}
	}
	writeJSON(w, visible)
}
