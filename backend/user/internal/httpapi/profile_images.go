package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"mtls/user/internal/models"
	"mtls/user/internal/repositories"
)

func (h *Handler) changeProfileImage(w http.ResponseWriter, r *http.Request) {
	viewer, ok := h.authenticate(w, r)
	if !ok {
		return
	}

	if r.Method == http.MethodPut && !h.allowParticipation(w, r, viewer.UserID) {
		return
	}

	slot := r.PathValue("slot")
	if slot != "avatar" && slot != "banner" {
		http.NotFound(w, r)
		return
	}

	var media *uuid.UUID
	if r.Method == http.MethodPut {
		var input struct {
			ID uuid.UUID `json:"media_id"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || input.ID == uuid.Nil {
			http.Error(w, "invalid profile image", http.StatusBadRequest)
			return
		}
		media = &input.ID
	} else if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	err := h.users.ChangeProfileImage(r.Context(), viewer.UserID, slot, media)
	if errors.Is(err, repositories.ErrProfileImageUnavailable) {
		http.NotFound(w, r)
		return
	}
	if h.handleUserError(w, err) {
		w.WriteHeader(http.StatusNoContent)
	}
}

func (h *Handler) profileImageHistory(w http.ResponseWriter, r *http.Request) {
	viewer, ok := h.authenticate(w, r)
	if !ok {
		return
	}

	var before int64
	if raw := r.URL.Query().Get("before"); raw != "" {
		value, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || value < 1 {
			http.Error(w, "invalid cursor", http.StatusBadRequest)
			return
		}
		before = value
	}

	changes, err := h.users.ProfileImageHistory(r.Context(), viewer.UserID, before)
	if !h.handleUserError(w, err) {
		return
	}

	var next string
	if len(changes) > 20 {
		changes = changes[:20]
		next = strconv.FormatInt(changes[19].ID, 10)
	}
	writeJSON(w, struct {
		Changes []models.ProfileImageChange `json:"changes"`
		Next    string                      `json:"next,omitempty"`
	}{changes, next})
}

func (h *Handler) profileImageAccess(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.accessibleAccount(w, r)
	if !ok {
		return
	}

	id, err := uuid.Parse(r.PathValue("media"))
	if err != nil || id == uuid.Nil {
		http.NotFound(w, r)
		return
	}
	images, err := h.users.ProfileImages(r.Context(), owner)
	if !h.handleUserError(w, err) {
		return
	}

	if (images.Avatar == nil || *images.Avatar != id) && (images.Banner == nil || *images.Banner != id) {
		http.NotFound(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
