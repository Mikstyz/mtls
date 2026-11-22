package httpapi

import (
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"
	sharedconfig "mtls/shared/config"
)

const scheduledPublicationCheckPath = "/internal/content/publication-check"

// ConfigureScheduledPublicationTLS is called after configuring the auth and media peers.
func (h *Handler) ConfigureScheduledPublicationTLS(clientURI, secret string) error {
	if h.peerClientURI == "" || !sharedconfig.ValidSPIFFEURI(clientURI) ||
		clientURI == h.peerClientURI || clientURI == h.mediaClientURI {
		return errors.New("scheduled publication requires TLS and a separate content client identity")
	}

	if len(secret) < 32 || len(secret) > 128 || strings.ContainsFunc(secret, func(r rune) bool { return r < 0x21 || r > 0x7e }) {
		return errors.New("invalid scheduled publication credential")
	}

	h.contentClientURI = clientURI
	h.publicationSecret = secret
	return nil
}

func (h *Handler) scheduledPublicationCheck(w http.ResponseWriter, r *http.Request) {
	credentials := r.Header.Values("X-Internal-Secret")
	secret := h.publicationSecret
	if h.contentClientURI == "" {
		secret = h.contentSearchSecret
	}
	if secret == "" || len(credentials) != 1 ||
		subtle.ConstantTimeCompare([]byte(credentials[0]), []byte(secret)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if h.contentClientURI != "" {
		if !sharedconfig.MatchesClientURI(r.TLS, h.contentClientURI) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	} else {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || !net.ParseIP(host).IsLoopback() {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	if len(r.URL.RawQuery) > 1200 {
		http.Error(w, "invalid publication check", http.StatusBadRequest)
		return
	}
	params, err := url.ParseQuery(r.URL.RawQuery)
	owner, ownerErr := uuid.Parse(params.Get("owner"))
	kind := params.Get("kind")
	ids := params["media"]
	if err != nil || ownerErr != nil || owner == uuid.Nil || len(params) != 3 || len(params["owner"]) != 1 || len(params["kind"]) != 1 ||
		(kind != "photo" && kind != "video") || len(ids) < 1 || len(ids) > 16 {
		http.Error(w, "invalid publication check", http.StatusBadRequest)
		return
	}
	seen := make(map[uuid.UUID]bool, len(ids))
	for _, raw := range ids {
		id, err := uuid.Parse(raw)
		if err != nil || id == uuid.Nil || seen[id] {
			http.Error(w, "invalid publication check", http.StatusBadRequest)
			return
		}
		seen[id] = true
	}

	active, err := h.activeAccounts(r.Context(), []uuid.UUID{owner})
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if !active[owner] {
		http.NotFound(w, r)
		return
	}

	const query = `SELECT count(*),MAX(duration_ms) FILTER (WHERE m.media_id=$4) FROM media_permissions m JOIN users u ON u.id=m.owner_id
 WHERE m.owner_id=$1 AND m.media_id=ANY($2::uuid[]) AND m.ready AND m.revoked_at IS NULL AND m.media_kind=$3`
	var count int
	var duration *int64
	if err := h.db.QueryRowContext(r.Context(), query, owner, pq.Array(ids), kind, ids[0]).Scan(&count, &duration); err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if count != len(ids) {
		http.NotFound(w, r)
		return
	}

	if duration != nil {
		w.Header().Set("X-Media-Duration-Ms", strconv.FormatInt(*duration, 10))
	}
	w.WriteHeader(http.StatusNoContent)
}
