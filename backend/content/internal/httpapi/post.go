package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"mtls/content/internal/catalog"
)

func (h *Handler) viewPublishedPost(w http.ResponseWriter, r *http.Request) {
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

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	viewer, err := h.user.author(ctx, r)

	if err != nil {
		writeContentError(w, r, err)
		return
	}

	post, err := h.catalog.PublishedPostForViewer(ctx, viewer, id)

	if err != nil {
		writeContentError(w, r, err)
		return
	}

	if post.AuthorID != viewer {
		if err := h.user.checkAuthorAccess(ctx, r, post.AuthorID); err != nil {
			writeContentError(w, r, err)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(post)
}

func (h *Handler) removeOwnPost(w http.ResponseWriter, r *http.Request) {
	h.changeAuthorRemoval(w, r, false)
}

func (h *Handler) restoreOwnPost(w http.ResponseWriter, r *http.Request) {
	h.changeAuthorRemoval(w, r, true)
}

func (h *Handler) changeAuthorRemoval(w http.ResponseWriter, r *http.Request, restore bool) {
	if !h.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if h.user == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	id, revision, ok := readPostRevision(w, r)
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	author, err := h.user.author(ctx, r)

	if err != nil {
		writeContentError(w, r, err)
		return
	}

	next, err := h.catalog.ChangeAuthorRemoval(ctx, author, id, revision, restore)

	if err != nil {
		writeContentError(w, r, err)
		return
	}

	writePostRevision(w, next)
}

func writeContentError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, errUnauthorized):
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	case errors.Is(err, errMediaUnavailable), errors.Is(err, catalog.ErrDraftNotFound), errors.Is(err, catalog.ErrPostNotFound):
		http.NotFound(w, r)
	case errors.Is(err, catalog.ErrInvalidDraft):
		http.Error(w, "invalid draft", http.StatusBadRequest)
	case errors.Is(err, catalog.ErrDraftVersionConflict):
		http.Error(w, "conflict", http.StatusConflict)
	default:
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}
}
