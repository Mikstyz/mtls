package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"mtls/shared/pagination"
)

type feedPosition struct {
	ID          uuid.UUID `json:"id"`
	PublishedAt time.Time `json:"published_at"`
}

type feedPost struct {
	feedPosition
	AuthorID     uuid.UUID  `json:"author_id"`
	Kind         string     `json:"kind"`
	Title        string     `json:"title"`
	CoverMediaID *uuid.UUID `json:"cover_media_id"`
}

type feedPage struct {
	Posts []feedPost    `json:"posts"`
	Next  *feedPosition `json:"next"`
}

func (h *Handler) feed(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	viewer, ok := h.authenticate(w, r.WithContext(ctx))
	if !ok {
		return
	}

	if len(r.URL.RawQuery) > 512 {
		http.Error(w, "invalid filter", http.StatusBadRequest)
		return
	}

	params, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || !validFeedParameters(params) {
		http.Error(w, "invalid filter", http.StatusBadRequest)
		return
	}

	if h.contentSearchURL == "" {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	scope := url.Values{"viewer": {viewer.UserID.String()}, "kind": {params.Get("kind")}, "author": {params.Get("author")}}
	cursor, err := pagination.NewCursor(h.contentSearchSecret, "mtls/user/feed-cursor/v1", scope.Encode())
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if params.Has("cursor") {
		id, position, err := cursor.Decode(params.Get("cursor"))
		if err != nil {
			http.Error(w, "invalid cursor", http.StatusBadRequest)
			return
		}
		params.Del("cursor")
		params.Set("before_time", position.Format(time.RFC3339Nano))
		params.Set("before_id", uuid.UUID(id).String())
	}

	page, err := h.fetchFeed(ctx, params.Encode())
	if errors.Is(err, errInvalidFeedFilter) {
		http.Error(w, "invalid filter", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	accounts := make([]uuid.UUID, 0, len(page.Posts)+1)
	accounts = append(accounts, viewer.UserID)
	seen := map[uuid.UUID]bool{viewer.UserID: true}
	for _, post := range page.Posts {
		if !seen[post.AuthorID] {
			accounts = append(accounts, post.AuthorID)
			seen[post.AuthorID] = true
		}
	}

	profiles, err := h.users.ExistingProfiles(ctx, accounts)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	active, err := h.activeAccounts(ctx, profiles)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if !active[viewer.UserID] {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	visible := page.Posts[:0]
	for _, post := range page.Posts {
		if active[post.AuthorID] {
			visible = append(visible, post)
		}
	}
	var next string
	if page.Next != nil {
		next, err = cursor.Encode(page.Next.ID, page.Next.PublishedAt)
		if err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
	}

	writeJSON(w, struct {
		Posts      []feedPost `json:"posts"`
		NextCursor string     `json:"next_cursor,omitempty"`
	}{Posts: visible, NextCursor: next})
}

var errInvalidFeedFilter = errors.New("invalid feed filter")

func validFeedParameters(params url.Values) bool {
	for name, values := range params {
		if len(values) != 1 || (name != "kind" && name != "author" && name != "limit" && name != "cursor") {
			return false
		}
	}
	return true
}

func (h *Handler) fetchFeed(ctx context.Context, rawQuery string) (feedPage, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, h.contentSearchURL+"/internal/feed/posts", nil)
	if err != nil {
		return feedPage{}, err
	}
	request.URL.RawQuery = rawQuery
	request.Header.Set("X-Internal-Secret", h.contentSearchSecret)

	response, err := h.client.Do(request)
	if err != nil {
		return feedPage{}, err
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusBadRequest {
		return feedPage{}, errInvalidFeedFilter
	}
	if response.StatusCode != http.StatusOK {
		return feedPage{}, errors.New("feed unavailable")
	}

	const maxFeedBytes = 128 << 10
	body, err := io.ReadAll(io.LimitReader(response.Body, maxFeedBytes+1))
	if err != nil || len(body) > maxFeedBytes {
		return feedPage{}, errors.New("invalid feed response")
	}

	var page feedPage
	decoder := json.NewDecoder(bytes.NewReader(body))
	if decoder.Decode(&page) != nil || decoder.Decode(new(any)) != io.EOF || page.Posts == nil || len(page.Posts) > 40 {
		return feedPage{}, errors.New("invalid feed response")
	}
	for _, post := range page.Posts {
		if post.ID == uuid.Nil || post.AuthorID == uuid.Nil || post.PublishedAt.IsZero() ||
			(post.Kind != "photo" && post.Kind != "video") || (post.CoverMediaID != nil && *post.CoverMediaID == uuid.Nil) {
			return feedPage{}, errors.New("invalid post in feed response")
		}
	}
	if page.Next != nil {
		if len(page.Posts) == 0 || page.Next.ID != page.Posts[len(page.Posts)-1].ID ||
			!page.Next.PublishedAt.Equal(page.Posts[len(page.Posts)-1].PublishedAt) {
			return feedPage{}, errors.New("invalid feed cursor")
		}
	}

	return page, nil
}
