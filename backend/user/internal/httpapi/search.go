package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"mtls/shared/pagination"
	"mtls/shared/searchtext"
)

func (h *Handler) SetSearchService(address, secret string) error {
	parsed, err := url.Parse(address)

	if err != nil || parsed == nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("invalid search service URL")
	}

	ip := net.ParseIP(parsed.Hostname())

	if ip == nil || !ip.IsLoopback() || len(secret) < 32 || len(secret) > 128 || secret == h.secret || secret == h.authServiceSecret {
		return errors.New("invalid search service settings")
	}

	for _, b := range []byte(secret) {
		if b < 0x21 || b > 0x7e {
			return errors.New("invalid search service settings")
		}
	}

	h.searchURL = strings.TrimRight(address, "/")
	h.searchSecret = secret
	return nil
}

func (h *Handler) searchUsers(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	page, ok := h.readSearchPage(w, r.WithContext(ctx), "user")
	if !ok {
		return
	}

	users, err := h.users.SearchCandidates(ctx, page.IDs, page.Query, page.Prefix)

	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	checkedIDs := make([]uuid.UUID, 0, len(users))

	for _, user := range users {
		checkedIDs = append(checkedIDs, user.ID)
	}

	active, err := h.activeAccounts(ctx, checkedIDs)

	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	visible := users[:0]
	for _, user := range users {
		if active[user.ID] {
			visible = append(visible, user)
		}
	}

	writeJSON(w, struct {
		Users      any    `json:"users"`
		NextCursor string `json:"next_cursor,omitempty"`
	}{Users: visible[:min(len(visible), page.Limit)], NextCursor: page.NextCursor})
}

type searchPage struct {
	Query      string
	Prefix     string
	Limit      int
	IDs        []uuid.UUID
	NextCursor string
}

type searchPosition struct {
	ID       uuid.UUID `json:"id"`
	Rank     *float32  `json:"rank"`
	Snapshot int64     `json:"snapshot"`
}

func (h *Handler) readSearchPage(w http.ResponseWriter, r *http.Request, kind string) (searchPage, bool) {
	viewer, ok := h.authenticateParticipant(w, r)
	if !ok {
		return searchPage{}, false
	}

	if len(r.URL.RawQuery) > 1024 {
		http.Error(w, "invalid query", http.StatusBadRequest)
		return searchPage{}, false
	}
	params, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		http.Error(w, "invalid query", http.StatusBadRequest)
		return searchPage{}, false
	}
	for key, values := range params {
		if len(values) != 1 || (key != "q" && key != "limit" && key != "cursor" && key != "suggest") {
			http.Error(w, "invalid query", http.StatusBadRequest)
			return searchPage{}, false
		}
	}

	query := params.Get("q")
	if !searchtext.Valid(query, "") || (params.Has("suggest") && (params.Get("suggest") != "1" || params.Has("cursor"))) {
		http.Error(w, "invalid query", http.StatusBadRequest)
		return searchPage{}, false
	}

	maxLimit := 50
	if params.Has("suggest") {
		maxLimit = 10
	}

	limit := maxLimit
	if params.Has("limit") {
		limit, err = strconv.Atoi(params.Get("limit"))
		if err != nil || limit < 1 || limit > maxLimit {
			http.Error(w, "invalid limit", http.StatusBadRequest)
			return searchPage{}, false
		}
	}

	if h.searchURL == "" || (kind == "content" && h.contentSearchURL == "") {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return searchPage{}, false
	}

	if params.Has("suggest") {
		complete, prefix, ok := searchtext.SplitPrefix(query)
		if !ok {
			return searchPage{IDs: []uuid.UUID{}, Limit: limit}, true
		}

		ids, _, err := h.searchCandidates(r.Context(), kind, complete, prefix, 30, nil)
		if err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return searchPage{}, false
		}

		return searchPage{Query: complete, Prefix: prefix, IDs: ids, Limit: limit}, true
	}

	scope := url.Values{"viewer": {viewer.UserID.String()}, "kind": {kind}, "q": {query}}
	cursor, err := pagination.NewCursor(h.searchSecret, "mtls/user/search-cursor/v1", scope.Encode())
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return searchPage{}, false
	}

	var before *searchPosition
	if params.Has("cursor") {
		id, rank, snapshot, err := cursor.DecodeSearch(params.Get("cursor"))
		if err != nil {
			http.Error(w, "invalid cursor", http.StatusBadRequest)
			return searchPage{}, false
		}
		before = &searchPosition{ID: id, Rank: &rank, Snapshot: snapshot}
	}

	ids, next, err := h.searchCandidates(r.Context(), kind, query, "", limit, before)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return searchPage{}, false
	}
	page := searchPage{Query: query, IDs: ids, Limit: limit}
	if next != nil {
		page.NextCursor, err = cursor.EncodeSearch(next.ID, *next.Rank, next.Snapshot)
		if err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return searchPage{}, false
		}
	}

	return page, true
}

// searchCandidates returns untrusted IDs; callers must recheck every result.
func (h *Handler) searchCandidates(ctx context.Context, kind, query, prefix string, limit int, before *searchPosition) ([]uuid.UUID, *searchPosition, error) {
	params := url.Values{"kind": {kind}, "q": {query}, "limit": {strconv.Itoa(limit)}}
	if prefix != "" {
		params.Set("prefix", prefix)
	}
	if before != nil {
		params.Set("before_id", before.ID.String())
		params.Set("before_rank", strconv.FormatFloat(float64(*before.Rank), 'g', -1, 32))
		params.Set("snapshot", strconv.FormatInt(before.Snapshot, 10))
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, h.searchURL+"/internal/search/page?"+params.Encode(), nil)
	if err != nil {
		return nil, nil, errors.New("cannot create search request")
	}

	request.Header.Set("X-Internal-Secret", h.searchSecret)
	response, err := h.client.Do(request)
	if err != nil {
		return nil, nil, errors.New("search unavailable")
	}

	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 16385))
	if err != nil || len(body) > 16384 || response.StatusCode != http.StatusOK {
		return nil, nil, errors.New("invalid search response")
	}

	var page struct {
		Candidates []struct {
			ID uuid.UUID `json:"id"`
		} `json:"candidates"`
		Next *searchPosition `json:"next"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()

	if decoder.Decode(&page) != nil || page.Candidates == nil || len(page.Candidates) > limit || decoder.Decode(new(any)) != io.EOF {
		return nil, nil, errors.New("invalid search response")
	}

	ids := make([]uuid.UUID, 0, len(page.Candidates))
	seen := make(map[uuid.UUID]struct{}, len(page.Candidates))
	for _, candidate := range page.Candidates {
		if candidate.ID == uuid.Nil || (before != nil && candidate.ID == before.ID) {
			return nil, nil, errors.New("invalid search candidate")
		}
		if _, exists := seen[candidate.ID]; exists {
			return nil, nil, errors.New("duplicate search candidate")
		}

		seen[candidate.ID] = struct{}{}
		ids = append(ids, candidate.ID)
	}

	if next := page.Next; next != nil {
		if len(ids) != limit || next.ID != ids[len(ids)-1] || next.Rank == nil || next.Snapshot <= 0 ||
			*next.Rank < 0 || math.IsNaN(float64(*next.Rank)) || math.IsInf(float64(*next.Rank), 0) ||
			(before != nil && (next.Snapshot != before.Snapshot || *next.Rank > *before.Rank ||
				(*next.Rank == *before.Rank && bytes.Compare(next.ID[:], before.ID[:]) <= 0))) {
			return nil, nil, errors.New("invalid search position")
		}
	}

	return ids, page.Next, nil
}
