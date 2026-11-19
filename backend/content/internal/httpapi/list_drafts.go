package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"
	"mtls/content/internal/catalog"
)

func (h *Handler) listDrafts(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if h.user == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	params, err := url.ParseQuery(r.URL.RawQuery)

	if err != nil {
		http.Error(w, "invalid filter", http.StatusBadRequest)
		return
	}

	for name, values := range params {
		if len(values) != 1 || (name != "limit" && name != "before_time" && name != "before_id") {
			http.Error(w, "invalid filter", http.StatusBadRequest)
			return
		}
	}

	limit := 20

	if params.Has("limit") {
		limit, err = strconv.Atoi(params.Get("limit"))

		if err != nil || limit < 1 || limit > 100 {
			http.Error(w, "invalid filter", http.StatusBadRequest)
			return
		}
	}

	if params.Has("before_time") != params.Has("before_id") {
		http.Error(w, "invalid filter", http.StatusBadRequest)
		return
	}

	var before *catalog.DraftCursor

	if params.Has("before_time") {
		created, err := time.Parse(time.RFC3339Nano, params.Get("before_time"))

		if err != nil || created.IsZero() {
			http.Error(w, "invalid filter", http.StatusBadRequest)
			return
		}

		id, err := uuid.Parse(params.Get("before_id"))

		if err != nil || id == uuid.Nil {
			http.Error(w, "invalid filter", http.StatusBadRequest)
			return
		}

		before = &catalog.DraftCursor{CreatedAt: created, ID: id}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	author, err := h.user.author(ctx, r)

	if errors.Is(err, errUnauthorized) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	drafts, err := h.catalog.ListDrafts(ctx, author, limit, before)

	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	type result struct {
		ID          uuid.UUID `json:"id"`
		Kind        string    `json:"kind"`
		Title       string    `json:"title"`
		Description string    `json:"description"`
		CreatedAt   time.Time `json:"created_at"`
		Revision    int64     `json:"revision"`
		MediaIDs    []string  `json:"media_ids"`
	}

	output := make([]result, 0, len(drafts))

	for _, draft := range drafts {
		output = append(output, result{draft.ID, draft.Kind, draft.Title, draft.Description, draft.CreatedAt, draft.Revision, draft.MediaIDs})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Drafts []result `json:"drafts"`
	}{output})
}
