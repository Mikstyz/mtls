package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"mtls/content/internal/catalog"
)

func (h *Handler) selectAd(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if h.user == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	operation, err := uuid.Parse(r.PathValue("request_id"))
	placement := r.PathValue("placement")
	if err != nil || operation == uuid.Nil || r.ContentLength != 0 || len(r.TransferEncoding) != 0 ||
		!validAdPlacement(placement) {
		http.Error(w, "invalid ad request", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	viewer, err := h.user.author(ctx, r)
	if err != nil {
		writeContentError(w, r, err)
		return
	}

	ad, err := h.catalog.SelectAd(ctx, viewer, operation, placement)
	if errors.Is(err, catalog.ErrAdRequestConflict) {
		http.Error(w, "request already used", http.StatusConflict)
		return
	}
	if err != nil {
		writeContentError(w, r, err)
		return
	}
	if ad == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ad)
}

func validAdPlacement(placement string) bool {
	return placement == "mixed_feed" || placement == "photo_feed" || placement == "video_feed"
}

func (h *Handler) reportAdImpression(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if h.user == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	operation, err := uuid.Parse(r.PathValue("request_id"))
	if err != nil || operation == uuid.Nil || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		http.Error(w, "invalid impression request", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	viewer, err := h.user.author(ctx, r)
	if err != nil {
		writeContentError(w, r, err)
		return
	}

	status, err := h.catalog.ReportAdImpression(ctx, viewer, operation)
	if err != nil {
		writeContentError(w, r, err)
		return
	}

	switch status {
	case http.StatusNoContent, http.StatusNotFound, http.StatusConflict, http.StatusGone:
		w.WriteHeader(status)
	default:
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}
}
