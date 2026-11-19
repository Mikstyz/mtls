package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTP client errors include request URLs, which can contain user identifiers.
func peerRequestError(err error) error {
	var requestError *url.Error

	if errors.As(err, &requestError) {
		return requestError.Err
	}

	return errors.New("peer request failed")
}

func (h *Handler) doPeerRequest(request *http.Request) (*http.Response, error) {
	h.peerRequests.Add(1)

	response, err := h.client.Do(request)

	if err != nil || response.StatusCode >= http.StatusInternalServerError {
		h.peerFailures.Add(1)
	}

	return response, err
}

func contextWithTimeout(r *http.Request, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), timeout)
}

// Bound the easiest timing difference between existing and unknown email addresses.
func padRecoveryResponse(ctx context.Context, started time.Time) {
	wait := time.Until(started.Add(200 * time.Millisecond))

	if wait <= 0 {
		return
	}

	timer := time.NewTimer(wait)
	defer timer.Stop()

	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}

func decodeJSON(w http.ResponseWriter, r *http.Request, value any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(value); err != nil {
		return err
	}

	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("request must contain one JSON value")
	}

	return nil
}

// The socket address is used intentionally; forwarded IP headers are untrusted.
func (h *Handler) allowLogin(r *http.Request, ip, identifier string) (bool, error) {
	ipAllowed, accountAllowed, err := h.checkLoginLimits(r, ip, identifier)

	return ipAllowed && accountAllowed, err
}

// checkLoginLimits keeps the IP and account limits separate for verified recovery.
func (h *Handler) checkLoginLimits(r *http.Request, ip, identifier string) (bool, bool, error) {
	const query = `
		INSERT INTO login_attempts (key_hash, window_started, attempts)
		VALUES ($1, CURRENT_TIMESTAMP, 1)
		ON CONFLICT (key_hash) DO UPDATE SET
			window_started = CASE WHEN login_attempts.window_started <= CURRENT_TIMESTAMP - INTERVAL '1 minute'
				THEN CURRENT_TIMESTAMP ELSE login_attempts.window_started END,
			attempts = CASE WHEN login_attempts.window_started <= CURRENT_TIMESTAMP - INTERVAL '1 minute'
				THEN 1 ELSE LEAST(login_attempts.attempts, 1000000) + 1 END
		RETURNING attempts
	`

	ctx, cancel := contextWithTimeout(r, 3*time.Second)
	defer cancel()

	limits := []struct {
		key   string
		limit int
	}{
		{key: "ip:" + ip, limit: 100},
		{key: "account:" + strings.ToLower(strings.TrimSpace(identifier)), limit: 10},
	}

	for index, item := range limits {
		mac := hmac.New(sha256.New, []byte(h.rateLimitSecret))
		_, _ = mac.Write([]byte("mtls-rate-limit-v1:" + item.key))
		key := mac.Sum(nil)
		var attempts int

		if index == 0 && h.rateGuard != nil {
			allowed, guardErr := h.rateGuard.Allow(ctx, key, item.limit*2)

			if guardErr == nil && !allowed {
				return false, false, nil
			}
		}

		if err := h.db.QueryRowContext(ctx, query, key).Scan(&attempts); err != nil {
			return false, false, err
		}

		if attempts > item.limit {
			return index != 0, false, nil
		}
	}

	return true, true, nil
}

// CleanupLoginAttempts removes old rate-limit entries in bounded batches.
func (h *Handler) CleanupLoginAttempts(ctx context.Context) error {
	const query = `
		DELETE FROM login_attempts
		WHERE key_hash IN (
			SELECT key_hash FROM login_attempts
			WHERE window_started < CURRENT_TIMESTAMP - INTERVAL '1 day'
			ORDER BY window_started
			LIMIT 500
			FOR UPDATE SKIP LOCKED
		)
	`

	_, err := h.db.ExecContext(ctx, query)

	return err
}

func (h *Handler) CleanupSessions(ctx context.Context) error {
	for range 10 {
		count, err := h.sessions.CleanupExpiredSessions(ctx)

		if err != nil {
			return err
		}

		if count == 0 {
			break
		}
	}

	return nil
}
