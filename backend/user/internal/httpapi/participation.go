package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
)

func (h *Handler) authenticateParticipant(w http.ResponseWriter, r *http.Request) (identity, bool) {
	actor, ok := h.authenticate(w, r)
	if !ok {
		return identity{}, false
	}

	if !h.allowParticipation(w, r, actor.UserID) {
		return identity{}, false
	}
	return actor, true
}

func (h *Handler) allowParticipation(w http.ResponseWriter, r *http.Request, owner uuid.UUID) bool {
	// Standalone user deployments have no content moderation authority.
	if h.contentSearchURL == "" {
		return true
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.contentSearchURL+"/internal/participation/"+owner.String(), nil)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return false
	}
	req.Header.Set("X-Internal-Secret", h.contentSearchSecret)
	resp, err := h.client.Do(req)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return false
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent:
		return true
	case http.StatusForbidden:
		http.Error(w, "participation restricted", http.StatusForbidden)
	default:
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}
	return false
}

func (h *Handler) participant(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.authenticateParticipant(w, r)
	if !ok {
		return
	}
	writeJSON(w, struct {
		ID uuid.UUID `json:"id"`
	}{actor.UserID})
}
