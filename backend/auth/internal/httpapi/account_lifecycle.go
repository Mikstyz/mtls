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
	"time"

	"github.com/google/uuid"

	"mtls/auth/internal/credentials"
)

var errLifecycleRejected = errors.New("user service rejected account operation")

func (h *Handler) deleteAccount(w http.ResponseWriter, r *http.Request) {
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

	if !h.allowRecovery(w, r, "delete:"+identity.UserID.String()) {
		return
	}

	revision, err := h.credentials.VerifyPasswordRevision(r.Context(), identity.UserID, request.Password)

	if errors.Is(err, credentials.ErrInvalidCredentials) {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	if err != nil {
		log.Printf("verify account deletion: %v", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	if err := h.credentials.BeginAccountDeletion(r.Context(), identity.UserID, identity.SessionID, revision, identity.TokenHash); err != nil {
		if errors.Is(err, credentials.ErrAccountLifecycle) {
			http.Error(w, "account operation unavailable", http.StatusConflict)
			return
		}

		log.Printf("begin account deletion: %v", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	h.clearCookie(w)
	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) restoreAccount(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Identifier string `json:"identifier"`
		Password   string `json:"password"`
	}

	if err := decodeJSON(w, r, &request); err != nil || len(request.Identifier) > 254 {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)

	if err != nil || net.ParseIP(ip) == nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	identifier := strings.ToLower(strings.TrimSpace(request.Identifier))
	allowed, err := h.allowLogin(r, ip, "restore:"+identifier)

	if err != nil {
		log.Printf("restore limiter: %v", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	if !allowed {
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}

	id, revision, err := h.credentials.VerifyDeleted(r.Context(), identifier, request.Password)

	if errors.Is(err, credentials.ErrInvalidCredentials) {
		http.Error(w, "invalid credentials or unavailable account", http.StatusUnauthorized)
		return
	}

	if err != nil {
		log.Printf("verify deleted account: %v", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	if err := h.credentials.BeginOwnerRestore(r.Context(), id, revision); err != nil {
		if errors.Is(err, credentials.ErrAccountLifecycle) {
			http.Error(w, "invalid credentials or unavailable account", http.StatusUnauthorized)
			return
		}

		log.Printf("restore account: %v", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) moderatorRestoreAccount(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.authenticate(w, r)

	if !ok {
		return
	}

	id, err := uuid.Parse(r.PathValue("id"))

	if err != nil || id == uuid.Nil {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}

	var request struct {
		Password string `json:"password"`
	}

	if err := decodeJSON(w, r, &request); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if !h.allowRecovery(w, r, "moderator:"+identity.UserID.String()) {
		return
	}

	revision, err := h.credentials.VerifyPasswordRevision(r.Context(), identity.UserID, request.Password)

	if errors.Is(err, credentials.ErrInvalidCredentials) {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	if err != nil {
		log.Printf("verify moderator: %v", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	if err := h.credentials.BeginModeratorRestore(r.Context(), identity.UserID, identity.SessionID, id, revision, identity.TokenHash); err != nil {
		if errors.Is(err, credentials.ErrAccountLifecycle) {
			http.Error(w, "account operation unavailable", http.StatusForbidden)
			return
		}

		log.Printf("moderator restore: %v", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) RunAccountLifecycle(ctx context.Context) {
	if h.recoveryMode {
		return
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			workCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			h.processAccountLifecycle(workCtx)
			cancel()
		}
	}
}

func (h *Handler) processAccountLifecycle(ctx context.Context) {
	job, err := h.credentials.ClaimAccountLifecycle(ctx)

	if errors.Is(err, sql.ErrNoRows) {
		return
	}

	if err != nil {
		log.Printf("claim account lifecycle: %v", err)
		return
	}

	if err := h.applyAccountLifecycle(ctx, job); err != nil {
		log.Printf("apply account lifecycle: %v", err)

		if errors.Is(err, errLifecycleRejected) && (job.State == "restoring_owner" || job.State == "restoring_moderator") {
			if rejectErr := h.credentials.RejectAccountRestore(ctx, job); rejectErr != nil {
				log.Printf("reject account restore: %v", rejectErr)
			}

			return
		}

		if retryErr := h.credentials.RetryAccountLifecycle(ctx, job); retryErr != nil {
			log.Printf("retry account lifecycle: %v", retryErr)
		}

		return
	}

	if err := h.credentials.CompleteAccountLifecycle(ctx, job); err != nil {
		log.Printf("complete account lifecycle: %v", err)
	}
}

func (h *Handler) applyAccountLifecycle(ctx context.Context, job credentials.AccountLifecycle) error {
	body, err := json.Marshal(struct {
		State     string    `json:"state"`
		DeletedAt time.Time `json:"deleted_at"`
	}{job.State, job.DeletedAt})

	if err != nil {
		return err
	}

	url := h.userURL + "/internal/users/" + job.UserID.String() + "/lifecycle/" + job.OperationID.String()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(body))

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

	if resp.StatusCode == http.StatusConflict {
		return errLifecycleRejected
	}

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("user service returned status %d", resp.StatusCode)
	}

	return nil
}
