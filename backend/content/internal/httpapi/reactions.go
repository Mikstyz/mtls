package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
)

func (h *Handler) setLike(w http.ResponseWriter, r *http.Request) {
	h.setReaction(w, r, "like")
}

func (h *Handler) setFavorite(w http.ResponseWriter, r *http.Request) {
	h.setReaction(w, r, "favorite")
}

func (h *Handler) setReaction(w http.ResponseWriter, r *http.Request, reaction string) {
	if !h.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if h.user == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil || id == uuid.Nil {
		http.NotFound(w, r)
		return
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	viewer, err := h.user.author(ctx, r)
	if err != nil {
		writeContentError(w, r, err)
		return
	}
	author, err := h.catalog.ViewablePostAuthor(ctx, viewer, id)
	if err != nil {
		writeContentError(w, r, err)
		return
	}
	if err := h.user.checkAuthorAccess(ctx, r, author); err != nil {
		writeContentError(w, r, err)
		return
	}

	if err := h.catalog.SetReaction(ctx, id, author, viewer, reaction, r.Method == http.MethodPut); err != nil {
		writeContentError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
