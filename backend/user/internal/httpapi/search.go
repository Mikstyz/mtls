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
	"unicode/utf8"

	"github.com/google/uuid"
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
	if _, ok := h.authenticate(w, r); !ok {
		return
	}

	query := r.URL.Query().Get("q")

	if strings.TrimSpace(query) == "" || len(query) > 256 || !utf8.ValidString(query) || strings.ContainsRune(query, 0) {
		http.Error(w, "invalid query", http.StatusBadRequest)
		return
	}

	ids, err := h.searchCandidates(r.Context(), "user", query)

	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	users, err := h.users.SearchCandidates(r.Context(), ids, query)

	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	checkedIDs := make([]uuid.UUID, 0, len(users))

	for _, user := range users {
		checkedIDs = append(checkedIDs, user.ID)
	}

	active, err := h.activeAccounts(r.Context(), checkedIDs)

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
		Users any `json:"users"`
	}{Users: visible})
}

// searchCandidates returns untrusted IDs; callers must recheck every result.
func (h *Handler) searchCandidates(ctx context.Context, kind, query string) ([]uuid.UUID, error) {
	if h.searchURL == "" {
		return nil, errors.New("search unavailable")
	}

	params := url.Values{"kind": {kind}, "q": {query}, "limit": {"50"}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, h.searchURL+"/internal/search?"+params.Encode(), nil)

	if err != nil {
		return nil, errors.New("cannot create search request")
	}

	request.Header.Set("X-Internal-Secret", h.searchSecret)
	response, err := h.client.Do(request)

	if err != nil {
		return nil, errors.New("search unavailable")
	}

	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 16385))

	if err != nil || len(body) > 16384 || response.StatusCode != http.StatusOK {
		return nil, errors.New("invalid search response")
	}

	var candidates []struct {
		ID uuid.UUID `json:"id"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()

	if decoder.Decode(&candidates) != nil || candidates == nil || len(candidates) > 50 || decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("invalid search response")
	}

	ids := make([]uuid.UUID, 0, len(candidates))
	seen := make(map[uuid.UUID]struct{}, len(candidates))

	for _, candidate := range candidates {
		if candidate.ID == uuid.Nil {
			return nil, errors.New("invalid search response")
		}

		if _, exists := seen[candidate.ID]; exists {
			continue
		}

		seen[candidate.ID] = struct{}{}
		ids = append(ids, candidate.ID)
	}

	return ids, nil
}
