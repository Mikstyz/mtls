package httpapi

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net/http"
	"strings"

	"mtls/auth/internal/credentials"
)

func (h *Handler) changeEmail(w http.ResponseWriter, r *http.Request) {
	if h.registrationMail == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	identity, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	if !h.allowRecovery(w, r, "email-change:"+identity.UserID.String()) {
		return
	}

	var err error
	if strings.HasSuffix(r.URL.Path, "/confirm") {
		var input struct {
			Token string `json:"token"`
		}
		if decodeJSON(w, r, &input) != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		err = h.credentials.ConfirmEmailChange(r.Context(), identity.UserID, identity.SessionID, identity.TokenHash, input.Token)
		if err == nil {
			h.clearCookie(w)
			w.WriteHeader(http.StatusNoContent)
			return
		}
	} else {
		var input struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if decodeJSON(w, r, &input) != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		var revision int64
		revision, err = h.credentials.VerifyPasswordRevision(r.Context(), identity.UserID, input.Password)
		if err == nil {
			err = h.credentials.RequestEmailChange(r.Context(), identity.UserID, identity.SessionID, revision, identity.TokenHash, input.Email, h.registrationKey)
		}
		if err == nil {
			w.WriteHeader(http.StatusAccepted)
			return
		}
	}

	switch {
	case errors.Is(err, credentials.ErrInvalidCredentials):
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
	case errors.Is(err, credentials.ErrInvalidConfirmation), errors.Is(err, credentials.ErrInvalidAccountDetails):
		http.Error(w, "invalid email change", http.StatusBadRequest)
	case errors.Is(err, credentials.ErrEmailUnavailable):
		http.Error(w, "email unavailable", http.StatusConflict)
	default:
		log.Print("email change failed")
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}
}

func (h *Handler) deliverEmailChange(ctx context.Context) {
	job, err := h.credentials.ClaimEmailChangeMail(ctx, h.registrationKey, h.previousDeliveryKeys()...)
	if errors.Is(err, sql.ErrNoRows) {
		return
	}
	if err != nil {
		log.Print("claim email change failed")
		return
	}
	if err = h.registrationMail.SendEmailChange(ctx, job.Email, job.Token); err != nil {
		log.Print("email change delivery failed")
		if h.credentials.RetryPasswordResetMail(ctx, job) != nil {
			log.Print("retry email change failed")
		}
		return
	}
	if h.credentials.CompletePasswordResetMail(ctx, job) != nil {
		log.Print("complete email change failed")
	}
}
