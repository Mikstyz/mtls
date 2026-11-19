package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
)

func (h *Handler) updatePrivacy(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.authenticate(w, r)

	if !ok {
		return
	}

	var request struct {
		PresenceVisibility string `json:"presence_visibility"`
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&request); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if err := decoder.Decode(new(any)); err != io.EOF {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if request.PresenceVisibility != "everyone" && request.PresenceVisibility != "nobody" {
		http.Error(w, "invalid presence visibility", http.StatusBadRequest)
		return
	}

	if err := h.users.UpdatePresenceVisibility(r.Context(), identity.UserID, request.PresenceVisibility); !h.handleUserError(w, err) {
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
