package httpapi

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
)

func (h *Handler) recordMediaView(w http.ResponseWriter, r *http.Request) {
	secrets := r.Header.Values("X-Internal-Secret")
	if h.mediaViewSecret == "" || len(secrets) != 1 ||
		subtle.ConstantTimeCompare([]byte(secrets[0]), []byte(h.mediaViewSecret)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	post, postErr := uuid.Parse(r.PathValue("id"))
	media, mediaErr := uuid.Parse(r.PathValue("media"))
	viewer := accessHeaderID(r.Header, "X-Viewer-ID")
	observedDays := r.Header.Values("X-View-Day")
	if postErr != nil || mediaErr != nil || post == uuid.Nil || media == uuid.Nil || viewer == uuid.Nil ||
		len(observedDays) != 1 || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		http.Error(w, "invalid view", http.StatusBadRequest)
		return
	}
	day, err := strconv.ParseInt(observedDays[0], 10, 32)
	if err != nil || day <= 0 {
		http.Error(w, "invalid view", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	if err := h.catalog.CountPostView(ctx, post, media, viewer, int32(day)); err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
