package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"mtls/content/internal/catalog"
	"mtls/shared/pagination"
)

func (h *Handler) ownerLibrary(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if h.user == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	if len(r.URL.RawQuery) > 256 {
		http.Error(w, "invalid library filter", http.StatusBadRequest)
		return
	}
	params, err := url.ParseQuery(r.URL.RawQuery)
	state := params.Get("state")
	if err != nil || len(params["state"]) > 1 || !catalog.ValidLibraryState(state) {
		http.Error(w, "invalid library filter", http.StatusBadRequest)
		return
	}
	params.Del("state")
	limit, token, ok := pageFilter(params.Encode())
	if !ok {
		http.Error(w, "invalid library filter", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	owner, err := h.user.sessionUser(ctx, r, "/api/users/me")
	if err != nil {
		writeContentError(w, r, err)
		return
	}

	cursor, err := pagination.NewCursor(h.secret, "mtls/content/owner-library/v1", owner.String()+"/"+state)
	if err != nil {
		writeContentError(w, r, err)
		return
	}
	var before *catalog.DraftCursor
	if token != "" {
		id, instant, err := cursor.Decode(token)
		if err != nil {
			http.Error(w, "invalid library cursor", http.StatusBadRequest)
			return
		}
		before = &catalog.DraftCursor{ID: id, CreatedAt: instant}
	}

	items, err := h.catalog.OwnerLibrary(ctx, owner, state, limit+1, before)
	if err != nil {
		writeContentError(w, r, err)
		return
	}

	var next string
	if len(items) > limit {
		items = items[:limit]
		last := items[len(items)-1]
		next, err = cursor.Encode(last.ID, last.CreatedAt)
		if err != nil {
			writeContentError(w, r, err)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Posts      []catalog.OwnerPost `json:"posts"`
		NextCursor string              `json:"next_cursor,omitempty"`
	}{Posts: items, NextCursor: next})
}
