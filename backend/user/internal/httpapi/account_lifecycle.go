package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"

	"mtls/user/internal/repositories"
)

func (h *Handler) internalAccountLifecycle(w http.ResponseWriter, r *http.Request) {
	if !h.authorizedInternal(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	userID, err := uuid.Parse(r.PathValue("id"))

	if err != nil || userID == uuid.Nil {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}

	operationID, err := uuid.Parse(r.PathValue("operation"))

	if err != nil || operationID == uuid.Nil {
		http.Error(w, "invalid operation id", http.StatusBadRequest)
		return
	}

	var request struct {
		State     string    `json:"state"`
		DeletedAt time.Time `json:"deleted_at"`
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

	err = h.users.ApplyAccountLifecycle(r.Context(), userID, operationID, request.State, request.DeletedAt)

	if errors.Is(err, repositories.ErrLifecycleConflict) {
		http.Error(w, "account operation conflict", http.StatusConflict)
		return
	}

	if !h.handleUserError(w, err) {
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
