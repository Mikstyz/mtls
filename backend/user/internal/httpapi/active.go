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
	"mtls/user/internal/models"
)

func (h *Handler) accountAccess(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.accessibleAccount(w, r); ok {
		w.WriteHeader(http.StatusNoContent)
	}
}

func (h *Handler) publicProfile(w http.ResponseWriter, r *http.Request) {
	author, ok := h.accessibleAccount(w, r)

	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	profile, err := h.users.GetById(ctx, author)

	if !h.handleUserError(w, err) {
		return
	}

	writeJSON(w, models.SearchUser{ID: profile.ID, Nickname: profile.Nickname})
}

func (h *Handler) accessibleAccount(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	requester, ok := h.authenticate(w, r.WithContext(ctx))

	if !ok {
		return uuid.Nil, false
	}

	author, err := uuid.Parse(r.PathValue("id"))

	if err != nil || author == uuid.Nil {
		http.NotFound(w, r)
		return uuid.Nil, false
	}

	accounts := []uuid.UUID{author}
	if requester.UserID != author {
		accounts = append(accounts, requester.UserID)
	}

	profiles, err := h.users.ExistingProfiles(ctx, accounts)

	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return uuid.Nil, false
	}
	if len(profiles) != len(accounts) {
		http.NotFound(w, r)
		return uuid.Nil, false
	}

	active, err := h.activeAccounts(ctx, accounts)

	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return uuid.Nil, false
	}
	if !active[author] || !active[requester.UserID] {
		http.NotFound(w, r)
		return uuid.Nil, false
	}

	return author, true
}

func (h *Handler) activeAccounts(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]bool, error) {
	active := make(map[uuid.UUID]bool, len(ids))

	if len(ids) == 0 {
		return active, nil
	}

	if len(ids) > 50 {
		return nil, errors.New("too many accounts")
	}

	requested := make(map[uuid.UUID]bool, len(ids))
	params := make(url.Values)

	for _, id := range ids {
		if id == uuid.Nil {
			return nil, errors.New("invalid account")
		}

		requested[id] = true
		params.Add("id", id.String())
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.authURL+"/internal/users/active?"+params.Encode(), nil)

	if err != nil {
		return nil, errors.New("cannot create account check")
	}

	req.Header.Set("X-Internal-Secret", h.authServiceSecret)
	resp, err := h.doPeerRequest(req)

	if err != nil {
		return nil, errors.New("account check unavailable")
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8193))

	if err != nil || len(body) > 8192 || resp.StatusCode != http.StatusOK {
		return nil, errors.New("account check unavailable")
	}

	var result []uuid.UUID
	decoder := json.NewDecoder(bytes.NewReader(body))

	if decoder.Decode(&result) != nil || len(result) > len(ids) || decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("invalid account check response")
	}

	for _, id := range result {
		if !requested[id] || active[id] {
			return nil, errors.New("invalid account check response")
		}

		active[id] = true
	}

	return active, nil
}
