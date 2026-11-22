package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

func (h *Handler) moderationPoints(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if h.user == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	owner, err := h.user.sessionUser(ctx, r, "/api/users/me")
	if err != nil {
		writeContentError(w, r, err)
		return
	}
	points, err := h.catalog.Points(ctx, owner)
	if err != nil {
		writeContentError(w, r, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(points)
}
