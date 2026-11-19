package httpapi

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net/http"

	"mtls/auth/internal/credentials"
)

func (h *Handler) requestEmailVerification(w http.ResponseWriter, r *http.Request) {
	if h.registrationMail == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	identity, ok := h.authenticate(w, r)

	if !ok {
		return
	}

	var request struct {
		Password string `json:"password"`
	}

	if err := decodeJSON(w, r, &request); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if !h.allowRecovery(w, r, "verify-email:"+identity.UserID.String()) {
		return
	}

	revision, err := h.credentials.VerifyPasswordRevision(r.Context(), identity.UserID, request.Password)

	if err != nil {
		if errors.Is(err, credentials.ErrInvalidCredentials) {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}

		log.Printf("verify email password: %v", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	if err := h.credentials.RequestEmailVerification(r.Context(), identity.UserID, identity.SessionID, revision, identity.TokenHash, h.registrationKey); err != nil {
		if errors.Is(err, credentials.ErrInvalidCredentials) {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}

		log.Printf("queue email verification: %v", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) confirmEmailVerification(w http.ResponseWriter, r *http.Request) {
	if h.registrationMail == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	var request struct {
		Token string `json:"token"`
	}

	if err := decodeJSON(w, r, &request); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if !h.allowRecovery(w, r, "reset-confirm") {
		return
	}

	err := h.credentials.ConfirmEmailVerification(r.Context(), request.Token)

	if errors.Is(err, credentials.ErrInvalidConfirmation) {
		http.Error(w, "invalid or expired confirmation", http.StatusBadRequest)
		return
	}

	if err != nil {
		log.Printf("confirm email verification: %v", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) deliverEmailVerification(ctx context.Context) {
	job, err := h.credentials.ClaimEmailVerificationMail(ctx, h.registrationKey, h.previousDeliveryKeys()...)

	if errors.Is(err, sql.ErrNoRows) {
		return
	}

	if err != nil {
		log.Printf("claim email verification: %v", err)
		return
	}

	if err := h.registrationMail.SendEmailVerification(ctx, job.Email, job.Token); err != nil {
		log.Print("email verification delivery failed")

		if retryErr := h.credentials.RetryPasswordResetMail(ctx, job); retryErr != nil {
			log.Printf("retry email verification: %v", retryErr)
		}

		return
	}

	if err := h.credentials.CompletePasswordResetMail(ctx, job); err != nil {
		log.Printf("complete email verification: %v", err)
	}
}
