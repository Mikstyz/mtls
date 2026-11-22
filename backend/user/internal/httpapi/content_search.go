package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

type contentSearchResult struct {
	ID           uuid.UUID  `json:"id"`
	AuthorID     uuid.UUID  `json:"author_id"`
	Kind         string     `json:"kind"`
	Title        string     `json:"title"`
	CoverMediaID *uuid.UUID `json:"cover_media_id,omitempty"`
}

// SetContentSearchService is called at startup before serving requests.
func (h *Handler) SetContentSearchService(address, secret string) error {
	parsed, err := url.Parse(address)

	if err != nil || parsed == nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("invalid content service URL")
	}

	ip := net.ParseIP(parsed.Hostname())

	if ip == nil || !ip.IsLoopback() || len(secret) < 32 || len(secret) > 128 || secret == h.secret || secret == h.authServiceSecret || secret == h.searchSecret {
		return errors.New("invalid content search settings")
	}

	for _, b := range []byte(secret) {
		if b < 0x21 || b > 0x7e {
			return errors.New("invalid content search settings")
		}
	}

	h.contentSearchURL = strings.TrimRight(address, "/")
	h.contentSearchSecret = secret
	return nil
}

func (h *Handler) searchContent(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	page, ok := h.readSearchPage(w, r.WithContext(ctx), "content")
	if !ok {
		return
	}

	results, err := h.recheckContentSearch(ctx, page.IDs, page.Query, page.Prefix)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	authors := make([]uuid.UUID, 0, len(results))
	seen := make(map[uuid.UUID]struct{}, len(results))

	for _, result := range results {
		if _, exists := seen[result.AuthorID]; !exists {
			seen[result.AuthorID] = struct{}{}
			authors = append(authors, result.AuthorID)
		}
	}

	profiles, err := h.users.ExistingProfiles(ctx, authors)

	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	active, err := h.activeAccounts(ctx, profiles)

	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	visible := results[:0]

	for _, result := range results {
		if active[result.AuthorID] {
			visible = append(visible, result)
		}
	}

	writeJSON(w, struct {
		Posts      []contentSearchResult `json:"posts"`
		NextCursor string                `json:"next_cursor,omitempty"`
	}{Posts: visible[:min(len(visible), page.Limit)], NextCursor: page.NextCursor})
}

func (h *Handler) recheckContentSearch(ctx context.Context, ids []uuid.UUID, query, prefix string) ([]contentSearchResult, error) {
	if len(ids) == 0 {
		return []contentSearchResult{}, nil
	}

	body, err := json.Marshal(struct {
		Query  string      `json:"query"`
		Prefix string      `json:"prefix,omitempty"`
		IDs    []uuid.UUID `json:"ids"`
	}{Query: query, Prefix: prefix, IDs: ids})

	if err != nil {
		return nil, errors.New("cannot encode content search")
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, h.contentSearchURL+"/internal/search/recheck", bytes.NewReader(body))

	if err != nil {
		return nil, errors.New("cannot create content search request")
	}

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Internal-Secret", h.contentSearchSecret)
	response, err := h.client.Do(request)

	if err != nil {
		return nil, errors.New("content search unavailable")
	}

	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 65537))

	if err != nil || len(data) > 65536 || response.StatusCode != http.StatusOK {
		return nil, errors.New("invalid content search response")
	}

	var results []contentSearchResult
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	if decoder.Decode(&results) != nil || results == nil || len(results) > len(ids) || decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("invalid content search response")
	}

	position := 0

	for _, result := range results {
		for position < len(ids) && ids[position] != result.ID {
			position++
		}

		if position == len(ids) || result.ID == uuid.Nil || result.AuthorID == uuid.Nil || (result.Kind != "photo" && result.Kind != "video") || len(result.Title) > 800 || !utf8.ValidString(result.Title) ||
			(result.CoverMediaID != nil && *result.CoverMediaID == uuid.Nil) {
			return nil, errors.New("invalid content search result")
		}

		position++
	}

	return results, nil
}
