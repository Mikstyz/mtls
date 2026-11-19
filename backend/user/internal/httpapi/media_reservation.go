package httpapi

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"

	"github.com/google/uuid"
	"mtls/user/internal/repositories"
)

// ConfigureMediaService is called at startup, after internal TLS is configured.
func (h *Handler) ConfigureMediaService(secret, previous, clientURI string) error {
	validSecret := func(value string) bool {
		if len(value) < 32 || len(value) > 128 {
			return false
		}

		for _, b := range []byte(value) {
			if b < 0x21 || b > 0x7e {
				return false
			}
		}

		return true
	}

	if !validSecret(secret) || (previous != "" && (!validSecret(previous) || previous == secret)) {
		return errors.New("invalid media service credential")
	}

	for _, value := range []string{secret, previous} {
		if value == "" {
			continue
		}

		if value == h.secret || value == h.previousSecret || value == h.authServiceSecret || value == h.searchSecret || value == h.contentSearchSecret {
			return errors.New("invalid media service credential")
		}
	}

	if (clientURI == "") != (h.peerClientURI == "") {
		return errors.New("media service identity must match internal TLS mode")
	}

	if clientURI != "" {
		identity, err := url.Parse(clientURI)

		if err != nil || identity == nil || identity.Scheme != "spiffe" || identity.Hostname() == "" || identity.Port() != "" || identity.Path == "" || identity.Path == "/" || identity.User != nil || identity.RawQuery != "" || identity.Fragment != "" || identity.Opaque != "" || clientURI == h.peerClientURI {
			return errors.New("invalid media service identity")
		}
	}

	h.mediaSecret = secret
	h.previousMediaSecret = previous
	h.mediaClientURI = clientURI
	return nil
}

func (h *Handler) authorizedMedia(r *http.Request) bool {
	values := r.Header.Values("X-Media-Service-Secret")

	if len(values) != 1 || h.mediaSecret == "" {
		return false
	}

	valid := subtle.ConstantTimeCompare([]byte(values[0]), []byte(h.mediaSecret))

	if h.previousMediaSecret != "" {
		valid |= subtle.ConstantTimeCompare([]byte(values[0]), []byte(h.previousMediaSecret))
	}

	return valid == 1
}

func (h *Handler) reserveMedia(w http.ResponseWriter, r *http.Request) {
	if !h.authorizedMedia(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	media, err := uuid.Parse(r.PathValue("id"))

	if err != nil || media == uuid.Nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	owners := r.Header.Values("X-Media-Owner")

	if len(owners) != 1 {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	owner, err := uuid.Parse(owners[0])

	if err != nil || owner == uuid.Nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	identity, ok := h.authenticate(w, r)

	if !ok {
		return
	}

	if identity.UserID != owner {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if err := h.users.ReserveMedia(r.Context(), identity.UserID, media); err != nil {
		if errors.Is(err, repositories.ErrMediaConflict) {
			http.Error(w, "media reservation conflict", http.StatusConflict)
			return
		}

		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// markMediaReady accepts a completed processing event from the media service.
func (h *Handler) markMediaReady(w http.ResponseWriter, r *http.Request) {
	kinds := r.Header.Values("X-Media-Kind")
	// Older photo workers only ever deliver photo readiness.
	kind := "photo"
	if len(kinds) == 1 {
		kind = kinds[0]
	}
	if len(kinds) > 1 || (kind != "photo" && kind != "video") {
		http.Error(w, "invalid media kind", http.StatusBadRequest)
		return
	}

	h.updateMediaPolicy(w, r, func(ctx context.Context, owner, media uuid.UUID) error {
		return h.users.MarkMediaReady(ctx, owner, media, kind)
	})
}

func (h *Handler) revokeMedia(w http.ResponseWriter, r *http.Request) {
	h.updateMediaPolicy(w, r, h.users.RevokeMedia)
}

func (h *Handler) updateMediaPolicy(w http.ResponseWriter, r *http.Request, update func(context.Context, uuid.UUID, uuid.UUID) error) {
	if !h.authorizedMedia(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	owners := r.Header.Values("X-Media-Owner")
	media, err := uuid.Parse(r.PathValue("id"))

	if err != nil || media == uuid.Nil || len(owners) != 1 || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	owner, err := uuid.Parse(owners[0])

	if err != nil || owner == uuid.Nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if err := update(r.Context(), owner, media); err != nil {
		if errors.Is(err, repositories.ErrMediaConflict) {
			http.Error(w, "media policy conflict", http.StatusConflict)
			return
		}

		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
