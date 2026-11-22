package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
)

func (h *Handler) setVideoCover(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if h.user == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	var input struct {
		Revision int64      `json:"revision"`
		MediaID  *uuid.UUID `json:"media_id"`
		Frame    *string    `json:"frame"`
	}
	id, ok := readPostCommand(w, r, &input)
	if !ok {
		return
	}
	if input.Frame != nil && (input.MediaID == nil || (*input.Frame != "poster-25.jpg" && *input.Frame != "poster-60.jpg")) {
		http.Error(w, "invalid cover frame", http.StatusBadRequest)
		return
	}

	if !validPostRevision(input.Revision) || input.MediaID != nil && *input.MediaID == uuid.Nil {
		http.Error(w, "invalid cover", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	author, err := h.user.author(ctx, r)
	if err != nil {
		writeContentError(w, r, err)
		return
	}
	if input.Frame != nil {
		cookie, err := r.Cookie(h.user.cookieName)
		if err != nil {
			writeContentError(w, r, errUnauthorized)
			return
		}
		if err := h.coverFrames.check(ctx, cookie, *input.MediaID, *input.Frame); err != nil {
			writeContentError(w, r, err)
			return
		}
	} else if input.MediaID != nil {
		kind, err := h.user.ownedMediaKind(ctx, r, *input.MediaID)
		if err != nil {
			writeContentError(w, r, err)
			return
		}
		if kind != "photo" {
			http.Error(w, "invalid cover media kind", http.StatusBadRequest)
			return
		}
	}

	if err := h.catalog.SetVideoCover(ctx, author, id, input.Revision, input.MediaID, input.Frame); err != nil {
		writeContentError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
