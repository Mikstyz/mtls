package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"mtls/content/internal/catalog"
	"mtls/shared/pagination"
)

// Test sales have their own routes and credential-gated storage operations.
func (h *Handler) testSales(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if h.user == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil || id == uuid.Nil {
		http.NotFound(w, r)
		return
	}
	viewer, err := h.user.author(r.Context(), r)
	if err != nil {
		writeContentError(w, r, err)
		return
	}

	if r.PathValue("order") != "" {
		h.purchaseTestOffer(w, r, id, viewer)
		return
	}
	if r.Method == http.MethodPut {
		var input struct {
			Revision int64  `json:"revision"`
			Amount   int64  `json:"amount_minor"`
			Currency string `json:"currency"`
		}
		if _, ok := readPostCommand(w, r, &input); !ok {
			return
		}
		if !validPostRevision(input.Revision) || input.Amount < 1 || input.Amount > 999999999 || (input.Currency != "RUB" && input.Currency != "USD" && input.Currency != "EUR") {
			http.Error(w, "invalid test offer", http.StatusBadRequest)
			return
		}
		offer := catalog.TestOffer{Revision: input.Revision, Amount: input.Amount, Currency: input.Currency}
		if err := h.catalog.CreateTestOffer(r.Context(), id, viewer, offer); err != nil {
			writeContentError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	offer, err := h.catalog.TestOffer(r.Context(), id)
	if err != nil {
		writeContentError(w, r, err)
		return
	}
	if err := h.user.checkAuthorAccess(r.Context(), r, offer.Author); err != nil {
		writeContentError(w, r, err)
		return
	}
	writeTestResult(w, http.StatusOK, offer)
}

func (h *Handler) purchaseTestOffer(w http.ResponseWriter, r *http.Request, id, viewer uuid.UUID) {
	request, err := uuid.Parse(r.PathValue("order"))
	if err != nil || request == uuid.Nil {
		http.NotFound(w, r)
		return
	}
	var input struct {
		Revision int64 `json:"revision"`
	}
	if _, ok := readPostCommand(w, r, &input); !ok {
		return
	}
	if !validPostRevision(input.Revision) {
		http.Error(w, "invalid edition", http.StatusBadRequest)
		return
	}

	offer, err := h.catalog.TestOffer(r.Context(), id)
	if err != nil {
		writeContentError(w, r, err)
		return
	}
	if err := h.user.checkAuthorAccess(r.Context(), r, offer.Author); err != nil {
		writeContentError(w, r, err)
		return
	}
	if offer.Revision != input.Revision {
		http.Error(w, "offer changed", http.StatusConflict)
		return
	}

	status, err := h.catalog.BuyTestOffer(r.Context(), id, viewer, request, input.Revision)
	if err != nil {
		writeContentError(w, r, err)
		return
	}
	switch status {
	case http.StatusOK, http.StatusCreated:
		receipt, err := h.catalog.TestReceipt(r.Context(), viewer, request)
		if err != nil {
			writeContentError(w, r, err)
			return
		}
		writeTestResult(w, status, receipt)
	case http.StatusNotFound, http.StatusConflict:
		w.WriteHeader(status)
	default:
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}
}

func (h *Handler) testOrder(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if h.user == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	id, err := uuid.Parse(r.PathValue("order"))
	if err != nil || id == uuid.Nil {
		http.NotFound(w, r)
		return
	}
	viewer, err := h.user.sessionUser(r.Context(), r, "/api/users/me")
	if err != nil {
		writeContentError(w, r, err)
		return
	}
	if r.Method == http.MethodDelete {
		if err := h.catalog.RevokeTestOrder(r.Context(), viewer, id); err != nil {
			writeContentError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	receipt, err := h.catalog.TestReceipt(r.Context(), viewer, id)
	if err != nil {
		writeContentError(w, r, err)
		return
	}
	writeTestResult(w, http.StatusOK, receipt)
}

func (h *Handler) testOrders(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if h.user == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	limit, token, ok := pageFilter(r.URL.RawQuery)
	if !ok {
		http.Error(w, "invalid order filter", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	buyer, err := h.user.sessionUser(ctx, r, "/api/users/me")
	if err != nil {
		writeContentError(w, r, err)
		return
	}

	cursor, err := pagination.NewCursor(h.secret, "mtls/content/test-order-history/v1", buyer.String())
	if err != nil {
		writeContentError(w, r, err)
		return
	}

	var before *catalog.TestReceiptCursor
	if token != "" {
		id, instant, err := cursor.Decode(token)
		if err != nil {
			http.Error(w, "invalid order cursor", http.StatusBadRequest)
			return
		}
		before = &catalog.TestReceiptCursor{Request: id, ConfirmedAt: instant}
	}

	orders, err := h.catalog.TestReceipts(ctx, buyer, limit+1, before)
	if err != nil {
		writeContentError(w, r, err)
		return
	}

	var next string
	if len(orders) > limit {
		orders = orders[:limit]
		last := orders[len(orders)-1]
		next, err = cursor.Encode(last.Request, last.ConfirmedAt)
		if err != nil {
			writeContentError(w, r, err)
			return
		}
	}

	writeTestResult(w, http.StatusOK, struct {
		Orders     []catalog.TestReceipt `json:"orders"`
		NextCursor string                `json:"next_cursor,omitempty"`
	}{Orders: orders, NextCursor: next})
}

func writeTestResult(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Mode string `json:"mode"`
		Data any    `json:"data"`
	}{"test", data})
}
