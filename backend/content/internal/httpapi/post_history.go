package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"mtls/content/internal/catalog"
)

func (h *Handler) postHistory(w http.ResponseWriter, r *http.Request) {
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

	var beforeRevision, beforeEvent int64
	if query := r.URL.RawQuery; query != "" {
		params, err := url.ParseQuery(query)
		if len(query) > 128 || err != nil || len(params) != 1 || len(params["before"]) != 1 {
			http.Error(w, "invalid history cursor", http.StatusBadRequest)
			return
		}

		revision, event, hasEvent := strings.Cut(params.Get("before"), ".")
		beforeRevision, err = strconv.ParseInt(revision, 10, 64)
		if err != nil || beforeRevision < 1 {
			http.Error(w, "invalid history cursor", http.StatusBadRequest)
			return
		}
		if hasEvent {
			beforeEvent, err = strconv.ParseInt(event, 10, 64)
			if err != nil || beforeEvent < 1 {
				http.Error(w, "invalid history cursor", http.StatusBadRequest)
				return
			}
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	author, err := h.user.sessionUser(ctx, r, "/api/users/me")
	if err != nil {
		writeContentError(w, r, err)
		return
	}
	items, err := h.catalog.PostHistory(ctx, author, id, beforeRevision, beforeEvent)
	if err != nil {
		writeContentError(w, r, err)
		return
	}

	var next string
	if len(items) > catalog.PostHistoryPageSize {
		items = items[:catalog.PostHistoryPageSize]
		last := items[len(items)-1]
		next = strconv.FormatInt(last.Revision, 10) + "." + strconv.FormatInt(last.EventID, 10)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Items []catalog.PostHistoryItem `json:"items"`
		Next  string                    `json:"next,omitempty"`
	}{Items: items, Next: next})
}
