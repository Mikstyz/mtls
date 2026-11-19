package httpapi

import (
	"net/http"

	sharedhealth "mtls/shared/health"
)

func (h *Handler) internalHealth(w http.ResponseWriter, r *http.Request) {
	if !h.authorizedInternal(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	h.health(w, r)
}

func (h *Handler) ready(w http.ResponseWriter, r *http.Request) {
	sharedhealth.Ready(w, r, h.db, h.client, h.userURL, h.userServiceSecret)
}
