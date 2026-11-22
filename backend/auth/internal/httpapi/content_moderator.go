package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
)

func (h *Handler) internalContentModerator(w http.ResponseWriter, r *http.Request) {
	h.internalSessionRole(w, r, "moderator")
}

func (h *Handler) internalAdOperator(w http.ResponseWriter, r *http.Request) {
	h.internalSessionRole(w, r, "ad_operator")
}

func (h *Handler) internalSessionRole(w http.ResponseWriter, r *http.Request, role string) {
	if !h.authorizedInternal(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	identity, ok := h.authenticate(w, r)
	if !ok {
		return
	}

	const query = `SELECT EXISTS (
  SELECT 1 FROM account_roles r JOIN credentials c USING(user_id)
  JOIN sessions s ON s.user_id=r.user_id AND s.id=$2
  WHERE r.user_id=$1 AND r.role=$3 AND c.enabled
  AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
  AND s.last_seen_at>clock_timestamp()-INTERVAL '168 hours'
  AND s.recovery_generation=(SELECT generation FROM session_epoch WHERE id)
  AND NOT EXISTS(SELECT 1 FROM account_deletions d WHERE d.user_id=r.user_id)
 )`
	var allowed bool
	if err := h.db.QueryRowContext(r.Context(), query, identity.UserID, identity.SessionID, role).Scan(&allowed); err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if !allowed {
		http.Error(w, role+" required", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		UserID    uuid.UUID `json:"user_id"`
		SessionID uuid.UUID `json:"session_id"`
	}{identity.UserID, identity.SessionID})
}
