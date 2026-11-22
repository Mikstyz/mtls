package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"mtls/content/internal/catalog"
)

func (h *Handler) adCampaignReport(w http.ResponseWriter, r *http.Request) {
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

	if _, err := h.user.sessionUser(ctx, r, "/api/users/me/ad-operator"); err != nil {
		writeContentError(w, r, err)
		return
	}

	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil || id == uuid.Nil {
		http.NotFound(w, r)
		return
	}

	params, err := url.ParseQuery(r.URL.RawQuery)
	if len(r.URL.RawQuery) > 128 || err != nil || len(params) != 2 || len(params["start"]) != 1 || len(params["end"]) != 1 {
		http.Error(w, "invalid report dates", http.StatusBadRequest)
		return
	}
	start, startErr := time.Parse(time.DateOnly, params.Get("start"))
	end, endErr := time.Parse(time.DateOnly, params.Get("end"))
	if startErr != nil || endErr != nil || start.Year() < 1 || !end.After(start) || end.After(start.AddDate(0, 0, 31)) {
		http.Error(w, "invalid report dates", http.StatusBadRequest)
		return
	}

	days, err := h.catalog.AdCampaignDailyReport(ctx, id, start, end)
	if err != nil {
		writeContentError(w, r, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	_ = json.NewEncoder(w).Encode(struct {
		Days []catalog.AdCampaignDay `json:"days"`
	}{Days: days})
}
