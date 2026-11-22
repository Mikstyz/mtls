package httpapi

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"mtls/auth/internal/credentials"
	"mtls/auth/internal/mailer"
)

func (h *Handler) ConfigureRegistration(key []byte, transport mailer.SMTP) error {
	if len(key) != 32 {
		return errors.New("registration delivery key must be 32 bytes")
	}

	if len(h.previousRegistrationKey) != 0 && bytes.Equal(key, h.previousRegistrationKey) {
		return errors.New("registration delivery keys must differ")
	}

	if err := transport.Validate(); err != nil {
		return err
	}

	h.registrationKey = append([]byte(nil), key...)
	h.registrationMail = &transport

	return nil
}

func (h *Handler) SetPreviousDeliveryKey(key []byte) error {
	if len(key) != 0 && (len(key) != 32 || bytes.Equal(key, h.registrationKey)) {
		return errors.New("previous delivery key must be distinct and 32 bytes")
	}

	h.previousRegistrationKey = append([]byte(nil), key...)
	return nil
}

func (h *Handler) previousDeliveryKeys() [][]byte {
	if len(h.previousRegistrationKey) == 0 {
		return nil
	}

	return [][]byte{h.previousRegistrationKey}
}

func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	if h.registrationMail == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	var request struct {
		Login    string `json:"login"`
		Email    string `json:"email"`
		Nickname string `json:"nickname"`
	}

	if err := decodeJSON(w, r, &request); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)

	if err != nil || net.ParseIP(ip) == nil || len(request.Email) > 254 {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	email := strings.ToLower(strings.TrimSpace(request.Email))
	allowed, err := h.allowLogin(r, ip, "registration:"+email)

	if err != nil {
		log.Printf("registration limiter: %v", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	if !allowed {
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}

	id, err := uuid.NewRandom()

	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	err = h.credentials.BeginRegistration(r.Context(), id, request.Login, email, request.Nickname, h.registrationKey)

	if errors.Is(err, credentials.ErrInvalidAccountDetails) {
		http.Error(w, "invalid account details", http.StatusBadRequest)
		return
	}

	var pgErr *pq.Error

	if err != nil && !(errors.As(err, &pgErr) && pgErr.Code == "23505") {
		log.Printf("begin registration: %v", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) confirmEmail(w http.ResponseWriter, r *http.Request) {
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

	ip, _, err := net.SplitHostPort(r.RemoteAddr)

	if err != nil || net.ParseIP(ip) == nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	allowed, err := h.allowLogin(r, ip, "confirmation:"+ip)

	if err != nil {
		log.Printf("confirmation limiter: %v", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	if !allowed {
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}

	_, _, err = h.credentials.ConfirmRegistration(r.Context(), request.Token, request.Password)

	if errors.Is(err, credentials.ErrInvalidConfirmation) {
		http.Error(w, "invalid or expired confirmation", http.StatusBadRequest)
		return
	}

	if errors.Is(err, credentials.ErrInvalidPassword) {
		http.Error(w, "invalid password", http.StatusBadRequest)
		return
	}

	if err != nil {
		log.Printf("confirm registration: %v", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) resendRegistration(w http.ResponseWriter, r *http.Request) {
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

	if !h.allowRecovery(w, r, "registration-resend:"+email) {
		return
	}

	started := time.Now()
	err := h.credentials.ResendRegistration(r.Context(), email, h.registrationKey)
	padRecoveryResponse(r.Context(), started)

	if errors.Is(err, credentials.ErrInvalidAccountDetails) {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if err != nil {
		log.Printf("resend registration: %v", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) RunRegistration(ctx context.Context) {
	if h.registrationMail == nil || h.recoveryMode {
		return
	}

	workers := []struct {
		timeout time.Duration
		run     func(context.Context)
	}{
		{30 * time.Second, h.deliverRegistration},
		{10 * time.Second, h.provisionRegistration},
		{30 * time.Second, h.deliverPasswordReset},
		{30 * time.Second, h.deliverEmailVerification},
		{30 * time.Second, h.deliverEmailChange},
	}

	var running sync.WaitGroup

	for _, worker := range workers {
		running.Add(1)

		go func() {
			defer running.Done()

			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if ctx.Err() != nil {
						return
					}

					workCtx, cancel := context.WithTimeout(ctx, worker.timeout)
					worker.run(workCtx)
					cancel()
				}
			}
		}()
	}

	running.Wait()
}

func (h *Handler) CleanupRegistrations(ctx context.Context) error {
	if err := h.credentials.CleanupExpiredRegistrations(ctx); err != nil {
		return err
	}

	return h.credentials.CleanupPasswordResets(ctx)
}

func (h *Handler) deliverRegistration(ctx context.Context) {
	job, err := h.credentials.ClaimRegistrationMail(ctx, h.registrationKey, h.previousDeliveryKeys()...)

	if errors.Is(err, sql.ErrNoRows) {
		return
	}

	if err != nil {
		log.Printf("claim registration email: %v", err)
		return
	}

	if err := h.registrationMail.SendConfirmation(ctx, job.Email, job.Token); err != nil {
		log.Print("registration email delivery failed")

		if retryErr := h.credentials.RetryRegistrationMail(ctx, job); retryErr != nil {
			log.Printf("retry registration email: %v", retryErr)
		}

		return
	}

	if err := h.credentials.CompleteRegistrationMail(ctx, job); err != nil {
		log.Printf("complete registration email: %v", err)
	}
}

func (h *Handler) provisionRegistration(ctx context.Context) {
	job, err := h.credentials.ClaimRegistrationProvision(ctx)

	if errors.Is(err, sql.ErrNoRows) {
		return
	}

	if err != nil {
		log.Printf("claim registration provision: %v", err)
		return
	}

	if err := h.createRegistrationProfile(ctx, job); err != nil {
		log.Printf("registration profile provision: %v", err)

		if retryErr := h.credentials.RetryRegistrationProvision(ctx, job); retryErr != nil {
			log.Printf("retry registration provision: %v", retryErr)
		}

		if job.Attempt >= credentials.MaxRegistrationProvisionAttempts {
			log.Print("registration provision paused after repeated failures; operator intervention required")
		}

		return
	}

	if err := h.credentials.ActivateRegistration(ctx, job); err != nil {
		log.Printf("activate registration: %v", err)

		if job.Attempt >= credentials.MaxRegistrationProvisionAttempts {
			log.Print("registration activation paused after repeated failures; operator intervention required")
		}
	}
}

func (h *Handler) createRegistrationProfile(ctx context.Context, job credentials.RegistrationProvision) error {
	body, err := json.Marshal(struct {
		Nickname   string    `json:"nickname"`
		ValidUntil time.Time `json:"valid_until"`
	}{job.Nickname, job.ValidUntil})

	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, h.userURL+"/internal/users/"+job.UserID.String(), bytes.NewReader(body))

	if err != nil {
		return errors.New("cannot construct user service request")
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Secret", h.userServiceSecret)
	resp, err := h.doPeerRequest(req)

	if err != nil {
		return peerRequestError(err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("user service returned status %d", resp.StatusCode)
	}

	return nil
}
