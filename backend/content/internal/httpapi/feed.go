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

func (h *Handler) feedCandidates(w http.ResponseWriter, r *http.Request) {
	h.serveFeed(w, r, true)
}

func (h *Handler) feedPosts(w http.ResponseWriter, r *http.Request) {
	h.serveFeed(w, r, false)
}

func (h *Handler) serveFeed(w http.ResponseWriter, r *http.Request, candidatesOnly bool) {
	if !h.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	filter, valid := readFeedFilter(r.URL.RawQuery)
	if !valid || (!candidatesOnly && (filter.Limit < 1 || filter.Limit > 40)) {
		http.Error(w, "invalid filter", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	limit := filter.Limit

	if !candidatesOnly {
		filter.Limit++
		if len(r.Header.Values("X-Viewer-ID")) != 0 {
			filter.Viewer = accessHeaderID(r.Header, "X-Viewer-ID")
			if filter.Viewer == uuid.Nil {
				http.Error(w, "invalid viewer", http.StatusBadRequest)
				return
			}
		}
	}

	posts, err := h.catalog.ListPublic(ctx, filter)
	if errors.Is(err, catalog.ErrInvalidFilter) {
		http.Error(w, "invalid filter", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if candidatesOnly {
		cards := make([]catalog.FeedPosition, 0, len(posts))
		for _, post := range posts {
			cards = append(cards, post.FeedPosition)
		}
		_ = json.NewEncoder(w).Encode(struct {
			Candidates []catalog.FeedPosition `json:"candidates"`
		}{Candidates: cards})
		return
	}

	var next *catalog.FeedPosition
	if len(posts) > limit {
		posts = posts[:limit]
		position := posts[limit-1].FeedPosition
		if filter.Recommended {
			position.PublishedAt = posts[limit-1].RecommendationPosition
		}
		next = &position
	}
	_ = json.NewEncoder(w).Encode(struct {
		Posts []catalog.FeedPost    `json:"posts"`
		Next  *catalog.FeedPosition `json:"next"`
	}{Posts: posts, Next: next})
}

func readFeedFilter(rawQuery string) (catalog.Filter, bool) {
	params, err := url.ParseQuery(rawQuery)

	if err != nil {
		return catalog.Filter{}, false
	}

	for name, list := range params {
		if len(list) != 1 || (name != "order" && name != "length" && name != "kind" && name != "author" && name != "limit" && name != "before_time" && name != "before_id") {
			return catalog.Filter{}, false
		}
	}

	order := params.Get("order")
	if order != "" && order != "recent" && order != "recommended" {
		return catalog.Filter{}, false
	}

	filter := catalog.Filter{Recommended: order == "recommended", Kind: params.Get("kind"), Length: params.Get("length"), Limit: 20}

	if params.Has("limit") {
		limit, err := strconv.Atoi(params.Get("limit"))

		if err != nil {
			return catalog.Filter{}, false
		}

		filter.Limit = limit
	}

	if params.Has("author") {
		id, err := uuid.Parse(params.Get("author"))

		if err != nil || id == uuid.Nil {
			return catalog.Filter{}, false
		}

		filter.Author = &id
	}

	if params.Has("before_time") != params.Has("before_id") {
		return catalog.Filter{}, false
	}

	if params.Has("before_time") {
		timestamp, err := time.Parse(time.RFC3339Nano, params.Get("before_time"))

		if err != nil || timestamp.IsZero() {
			return catalog.Filter{}, false
		}

		id, err := uuid.Parse(params.Get("before_id"))

		if err != nil || id == uuid.Nil {
			return catalog.Filter{}, false
		}

		filter.Before = &catalog.Cursor{PublishedAt: timestamp, ID: id}
	}

	return filter, true
}
