package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

func (h *Handler) schedulePost(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if h.user == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	input := struct {
		Revision   int64           `json:"revision"`
		PublishAt  json.RawMessage `json:"publish_at"`
		Visibility string          `json:"visibility"`
	}{Visibility: "private"}
	id, ok := readPostCommand(w, r, &input)
	if !ok {
		return
	}

	var publishAt *time.Time
	if json.Unmarshal(input.PublishAt, &publishAt) != nil || !validPostRevision(input.Revision) ||
		(input.Visibility != "private" && input.Visibility != "public") ||
		(publishAt != nil && !publishAt.Equal(publishAt.Truncate(time.Minute))) {
		http.Error(w, "invalid schedule", http.StatusBadRequest)
		return
	}

	if publishAt != nil {
		utc := publishAt.UTC()
		publishAt = &utc
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	sessionPath := "/api/users/me/participation"
	if publishAt == nil {
		sessionPath = "/api/users/me"
	}
	owner, err := h.user.sessionUser(ctx, r, sessionPath)
	if err != nil {
		writeContentError(w, r, err)
		return
	}

	status, err := h.catalog.SchedulePost(ctx, owner, id, input.Revision, publishAt, input.Visibility)
	if err != nil {
		writeContentError(w, r, err)
		return
	}
	switch status {
	case http.StatusNoContent, http.StatusBadRequest, http.StatusConflict, http.StatusNotFound:
		w.WriteHeader(status)
	default:
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}
}
