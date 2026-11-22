package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"mtls/content/internal/catalog"
)

func (h *Handler) adCampaigns(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if h.user == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	actor, err := h.user.sessionUser(ctx, r, "/api/users/me/ad-operator")
	if err != nil {
		writeContentError(w, r, err)
		return
	}

	if r.Method == http.MethodPut {
		h.putAdCampaign(ctx, w, r, actor)
		return
	}

	limit, token, ok := pageFilter(r.URL.RawQuery)
	if !ok {
		http.Error(w, "invalid campaign filter", http.StatusBadRequest)
		return
	}

	var after *uuid.UUID
	if token != "" {
		parsed, err := uuid.Parse(token)
		if err != nil || parsed == uuid.Nil || parsed.String() != token {
			http.Error(w, "invalid campaign cursor", http.StatusBadRequest)
			return
		}
		after = &parsed
	}

	campaigns, err := h.catalog.AdCampaigns(ctx, after, limit+1)
	if err != nil {
		writeContentError(w, r, err)
		return
	}
	var next string
	if len(campaigns) > limit {
		campaigns = campaigns[:limit]
		next = campaigns[len(campaigns)-1].ID.String()
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Campaigns  []catalog.AdCampaign `json:"campaigns"`
		NextCursor string               `json:"next_cursor,omitempty"`
	}{Campaigns: campaigns, NextCursor: next})
}

func (h *Handler) putAdCampaign(ctx context.Context, w http.ResponseWriter, r *http.Request, actor uuid.UUID) {
	var input struct {
		Revision *int64 `json:"revision"`
		catalog.AdCampaignSettings
	}
	id, ok := readPostCommandLimit(w, r, &input, 2048)
	if !ok {
		return
	}

	input.Headline = strings.TrimSpace(input.Headline)
	if input.Revision == nil || (*input.Revision != 0 && !validPostRevision(*input.Revision)) ||
		input.Enabled == nil || !validAdPlacement(input.Placement) || !validAdPlacement(input.Destination) ||
		input.Headline == "" || utf8.RuneCountInString(input.Headline) > 140 ||
		strings.ContainsFunc(input.Headline, unicode.IsControl) || input.StartsAt.IsZero() ||
		!input.EndsAt.After(input.StartsAt) || input.Budget < 1 {
		http.Error(w, "invalid ad campaign", http.StatusBadRequest)
		return
	}

	status, err := h.catalog.PutAdCampaign(ctx, actor, id, *input.Revision, input.AdCampaignSettings)
	if err != nil {
		writeContentError(w, r, err)
		return
	}

	switch status {
	case http.StatusCreated, http.StatusNoContent, http.StatusBadRequest, http.StatusNotFound, http.StatusConflict:
		w.WriteHeader(status)
	default:
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}
}
