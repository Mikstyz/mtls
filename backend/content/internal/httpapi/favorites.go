package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"
	"mtls/content/internal/catalog"
	"mtls/shared/pagination"
)

func (h *Handler) favorites(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if h.user == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	limit, token, valid := favoriteFilter(r.URL.RawQuery)
	if !valid {
		http.Error(w, "invalid filter", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	viewer, err := h.user.author(ctx, r)
	if err != nil {
		writeContentError(w, r, err)
		return
	}

	cursor, err := pagination.NewCursor(h.secret, "mtls/content/favorites-cursor/v1", viewer.String())
	if err != nil {
		writeContentError(w, r, err)
		return
	}
	var before *catalog.FavoriteCursor
	if token != "" {
		id, position, err := cursor.Decode(token)
		if err != nil {
			http.Error(w, "invalid cursor", http.StatusBadRequest)
			return
		}
		before = &catalog.FavoriteCursor{ID: id, AddedAt: position}
	}

	items, err := h.catalog.ListFavorites(ctx, viewer, limit+1, before)
	if err != nil {
		writeContentError(w, r, err)
		return
	}

	var next string
	if len(items) > limit {
		items = items[:limit]
		last := items[limit-1]
		next, err = cursor.Encode(last.ID, last.AddedAt)
		if err != nil {
			writeContentError(w, r, err)
			return
		}
	}

	active, err := h.user.activeFavoriteAuthors(ctx, r, items)
	if err != nil {
		writeContentError(w, r, err)
		return
	}

	visible := items[:0]
	for _, item := range items {
		if active[item.AuthorID] {
			visible = append(visible, item)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Favorites  []catalog.Favorite `json:"favorites"`
		NextCursor string             `json:"next_cursor,omitempty"`
	}{Favorites: visible, NextCursor: next})
}

func favoriteFilter(raw string) (int, string, bool) {
	if len(raw) > 256 {
		return 0, "", false
	}
	params, err := url.ParseQuery(raw)
	if err != nil {
		return 0, "", false
	}
	for name, values := range params {
		if len(values) != 1 || values[0] == "" || (name != "limit" && name != "cursor") {
			return 0, "", false
		}
	}

	limit := 20
	if params.Has("limit") {
		limit, err = strconv.Atoi(params.Get("limit"))
		if err != nil || limit < 1 || limit > 40 {
			return 0, "", false
		}
	}
	return limit, params.Get("cursor"), true
}

func (u *userClient) activeFavoriteAuthors(ctx context.Context, r *http.Request, items []catalog.Favorite) (map[uuid.UUID]bool, error) {
	active := make(map[uuid.UUID]bool, len(items))
	if len(items) == 0 {
		return active, nil
	}

	cookie, err := r.Cookie(u.cookieName)
	if err != nil {
		return nil, errUnauthorized
	}

	params := make(url.Values)
	requested := make(map[uuid.UUID]bool, len(items))
	for _, item := range items {
		if !requested[item.AuthorID] {
			params.Add("id", item.AuthorID.String())
			requested[item.AuthorID] = true
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.url+"/api/users/accounts/active?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.AddCookie(cookie)

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, errUnauthorized
	}
	const maxBytes = 2048
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil || resp.StatusCode != http.StatusOK || len(body) > maxBytes {
		return nil, errors.New("author access unavailable")
	}

	var ids []uuid.UUID
	decoder := json.NewDecoder(bytes.NewReader(body))
	if decoder.Decode(&ids) != nil || decoder.Decode(new(any)) != io.EOF || ids == nil {
		return nil, errors.New("invalid author access response")
	}
	for _, id := range ids {
		if !requested[id] || active[id] {
			return nil, errors.New("unexpected author ID")
		}
		active[id] = true
	}
	return active, nil
}
