package httpapi

import (
	"fmt"
	"net/http"
	"time"

	"mtls/auth/internal/credentials"
)

// internalMetrics exposes aggregate queue state only to an authenticated peer.
func (h *Handler) internalMetrics(w http.ResponseWriter, r *http.Request) {
	if !h.authorizedInternal(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	ctx, cancel := contextWithTimeout(r, 2*time.Second)
	defer cancel()

	const query = `SELECT
		(SELECT count(*) FROM registrations r JOIN credentials c ON c.user_id = r.user_id
			WHERE r.confirmed_at IS NOT NULL AND NOT c.enabled AND r.provision_attempts < $1),
		(SELECT count(*) FROM registrations r JOIN credentials c ON c.user_id = r.user_id
			WHERE r.confirmed_at IS NOT NULL AND NOT c.enabled AND r.provision_attempts >= $1
				AND (r.provision_lease_until IS NULL OR r.provision_lease_until <= clock_timestamp())),
		(SELECT count(*) FROM registration_mail_jobs j JOIN registrations r ON r.user_id = j.user_id
			WHERE r.confirmed_at IS NULL AND r.expires_at > CURRENT_TIMESTAMP),
		(SELECT count(*) FROM password_resets WHERE token_ciphertext IS NOT NULL AND expires_at > CURRENT_TIMESTAMP),
		(SELECT count(*) FROM account_deletions WHERE state <> 'deleted'),
		(SELECT count(*) FROM security_event_outbox WHERE published_at IS NULL),
		(SELECT COALESCE(GREATEST(0, EXTRACT(EPOCH FROM (clock_timestamp() - min(created_at)))::bigint), 0)
			FROM security_event_outbox WHERE published_at IS NULL)`

	var pending, paused, registrationMail, accountMail, lifecycle, securityPending, securityOldest int64
	if err := h.db.QueryRowContext(ctx, query, credentials.MaxRegistrationProvisionAttempts).Scan(
		&pending, &paused, &registrationMail, &accountMail, &lifecycle, &securityPending, &securityOldest,
	); err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = fmt.Fprintf(w, "# TYPE mtls_auth_registration_provision_pending gauge\nmtls_auth_registration_provision_pending %d\n"+
		"# TYPE mtls_auth_registration_provision_paused gauge\nmtls_auth_registration_provision_paused %d\n"+
		"# TYPE mtls_auth_registration_mail_pending gauge\nmtls_auth_registration_mail_pending %d\n"+
		"# TYPE mtls_auth_account_mail_pending gauge\nmtls_auth_account_mail_pending %d\n"+
		"# TYPE mtls_auth_account_lifecycle_pending gauge\nmtls_auth_account_lifecycle_pending %d\n"+
		"# TYPE mtls_auth_security_outbox_pending gauge\nmtls_auth_security_outbox_pending %d\n"+
		"# TYPE mtls_auth_security_outbox_oldest_seconds gauge\nmtls_auth_security_outbox_oldest_seconds %d\n",
		pending, paused, registrationMail, accountMail, lifecycle, securityPending, securityOldest)

	_, _ = fmt.Fprintf(w, "# TYPE mtls_auth_peer_requests_total counter\nmtls_auth_peer_requests_total %d\n"+
		"# TYPE mtls_auth_peer_failures_total counter\nmtls_auth_peer_failures_total %d\n",
		h.peerRequests.Load(), h.peerFailures.Load())

	if guard, ok := h.rateGuard.(interface{ Stats() (uint64, uint64) }); ok {
		blocked, fallbacks := guard.Stats()
		_, _ = fmt.Fprintf(w, "# TYPE mtls_auth_redis_guard_blocked_total counter\nmtls_auth_redis_guard_blocked_total %d\n"+
			"# TYPE mtls_auth_redis_guard_fallback_total counter\nmtls_auth_redis_guard_fallback_total %d\n", blocked, fallbacks)
	}

	if cache, ok := h.sessionCache.(interface {
		Stats() (uint64, uint64, uint64)
	}); ok {
		hits, misses, failures := cache.Stats()
		_, _ = fmt.Fprintf(w, "# TYPE mtls_auth_session_cache_hits_total counter\nmtls_auth_session_cache_hits_total %d\n"+
			"# TYPE mtls_auth_session_cache_misses_total counter\nmtls_auth_session_cache_misses_total %d\n"+
			"# TYPE mtls_auth_session_cache_failures_total counter\nmtls_auth_session_cache_failures_total %d\n", hits, misses, failures)
	}
}
