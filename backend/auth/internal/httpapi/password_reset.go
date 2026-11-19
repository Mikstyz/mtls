package httpapi

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"mtls/auth/internal/credentials"
)

func (h *Handler) requestPasswordReset(w http.ResponseWriter, r *http.Request) {
	if h.registrationMail == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	var request struct {
		Email string `json:"email"`
	}

	if err := decodeJSON(w, r, &request); err != nil || len(request.Email) == 0 || len(request.Email) > 254 {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	email := strings.ToLower(strings.TrimSpace(request.Email))

	if email == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if !h.allowRecovery(w, r, "reset:"+email) {
		return
	}

	started := time.Now()
	err := h.credentials.RequestPasswordReset(r.Context(), email, h.registrationKey)
	padRecoveryResponse(r.Context(), started)

	if err != nil {
		log.Printf("queue password reset: %v", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) confirmPasswordReset(w http.ResponseWriter, r *http.Request) {
	if h.registrationMail == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	var request struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}

	if err := decodeJSON(w, r, &request); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if !h.allowRecovery(w, r, "reset-confirm") {
		return
	}

	err := h.credentials.ResetPassword(r.Context(), request.Token, request.Password)

	if errors.Is(err, credentials.ErrInvalidPassword) || errors.Is(err, credentials.ErrInvalidReset) {
		http.Error(w, "invalid or expired reset", http.StatusBadRequest)
		return
	}

	if err != nil {
		log.Printf("reset password: %v", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	h.clearCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) allowRecovery(w http.ResponseWriter, r *http.Request, identifier string) bool {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)

	if err != nil || net.ParseIP(ip) == nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return false
	}

	if identifier == "reset-confirm" {
		identifier += ":" + ip
	}

	allowed, err := h.allowLogin(r, ip, identifier)

	if err != nil {
		log.Printf("password reset limiter: %v", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return false
	}

	if !allowed {
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return false
	}

	return true
}

func (h *Handler) deliverPasswordReset(ctx context.Context) {
	job, err := h.credentials.ClaimPasswordResetMail(ctx, h.registrationKey, h.previousDeliveryKeys()...)

	if errors.Is(err, sql.ErrNoRows) {
		return
	}

	if err != nil {
		log.Printf("claim password reset email: %v", err)
		return
	}

	if err := h.registrationMail.SendPasswordReset(ctx, job.Email, job.Token); err != nil {
		log.Print("password reset email delivery failed")

		if retryErr := h.credentials.RetryPasswordResetMail(ctx, job); retryErr != nil {
			log.Printf("retry password reset email: %v", retryErr)
		}

		return
	}

	if err := h.credentials.CompletePasswordResetMail(ctx, job); err != nil {
		log.Printf("complete password reset email: %v", err)
	}
}
