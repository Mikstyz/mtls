package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// postMediaAccess returns the current catalog decision to user, which checks
// the session, file readiness, and account state.
func (h *Handler) postMediaAccess(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	post, postErr := uuid.Parse(r.PathValue("id"))
	media, mediaErr := uuid.Parse(r.PathValue("media"))
	owner := accessHeaderID(r.Header, "X-Media-Owner")
	viewer := accessHeaderID(r.Header, "X-Viewer-ID")

	if postErr != nil || mediaErr != nil || post == uuid.Nil || media == uuid.Nil || owner == uuid.Nil || viewer == uuid.Nil {
		http.NotFound(w, r)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	allowed, err := h.catalog.AllowsPostMedia(ctx, post, media, owner, viewer)

	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if !allowed {
		http.NotFound(w, r)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func accessHeaderID(header http.Header, name string) uuid.UUID {
	values := header.Values(name)

	if len(values) != 1 {
		return uuid.Nil
	}

	id, err := uuid.Parse(values[0])

	if err != nil {
		return uuid.Nil
	}

	return id
}
