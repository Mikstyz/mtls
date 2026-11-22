package httpapi

import (
	"net/http"

	"github.com/google/uuid"
)

func (h *Handler) contentModerator(w http.ResponseWriter, r *http.Request) {
	h.accountRole(w, r, "/internal/session/moderator")
}

func (h *Handler) adOperator(w http.ResponseWriter, r *http.Request) {
	h.accountRole(w, r, "/internal/session/ad-operator")
}

func (h *Handler) accountRole(w http.ResponseWriter, r *http.Request, path string) {
	actor, ok := h.authenticateSession(w, r, path)
	if !ok {
		return
	}

	if _, err := h.users.GetById(r.Context(), actor.UserID); !h.handleUserError(w, err) {
		return
	}

	writeJSON(w, struct {
		ID uuid.UUID `json:"id"`
	}{actor.UserID})
}
