package uploadhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"mtls/media-processing/internal/lifecycle"
)

func (h *handler) history(w http.ResponseWriter, r *http.Request) {
	token, ok := h.authorize(w, r)
	if !ok {
		return
	}

	before, ok := historyCursor(r.URL.RawQuery)
	if !ok {
		http.Error(w, "invalid history cursor", http.StatusBadRequest)
		return
	}

	if !h.acquire(w) {
		return
	}
	defer func() { <-h.slots }()

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	items, err := h.service.History(ctx, token, before)
	if err != nil {
		writeError(w, err)
		return
	}

	var next *lifecycle.UploadPosition
	if len(items) > lifecycle.UploadHistoryPageSize {
		items = items[:lifecycle.UploadHistoryPageSize]
		next = &items[len(items)-1].UploadPosition
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Items []lifecycle.UploadHistoryItem `json:"items"`
		Next  *lifecycle.UploadPosition     `json:"next,omitempty"`
	}{Items: items, Next: next})
}

func historyCursor(query string) (*lifecycle.UploadPosition, bool) {
	if query == "" {
		return nil, true
	}
	if len(query) > 256 {
		return nil, false
	}

	params, err := url.ParseQuery(query)
	if err != nil || len(params) != 2 || len(params["before_time"]) != 1 || len(params["before_id"]) != 1 {
		return nil, false
	}

	instant, timeErr := time.Parse(time.RFC3339Nano, params.Get("before_time"))
	id, idErr := uuid.Parse(params.Get("before_id"))
	if timeErr != nil || idErr != nil || instant.IsZero() || id == uuid.Nil {
		return nil, false
	}

	return &lifecycle.UploadPosition{ID: id, CreatedAt: instant}, true
}
