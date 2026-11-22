package httpapi

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"mtls/auth/internal/credentials"
	"mtls/auth/internal/mailer"
	"mtls/auth/internal/sessions"
	sharedconfig "mtls/shared/config"
	sharedhealth "mtls/shared/health"
)

type Handler struct {
	db                      *sql.DB
	credentials             *credentials.Store
	sessions                *sessions.Store
	origin                  string
	secure                  bool
	cookieName              string
	internalSecret          string
	previousInternalSecret  string
	userServiceSecret       string
	rateLimitSecret         string
	userURL                 string
	client                  *http.Client
	registrationMail        *mailer.SMTP
	registrationKey         []byte
	previousRegistrationKey []byte
	peerClientURI           string
	recoveryMode            bool
	peerRequests            atomic.Uint64
	peerFailures            atomic.Uint64
	rateGuard               rateGuard
	sessionCache            sessions.Cache
}

type rateGuard interface {
	Allow(context.Context, []byte, int) (bool, error)
}

// SetRateGuard is called during startup before the handler serves requests.
func (h *Handler) SetRateGuard(guard rateGuard) {
	h.rateGuard = guard
}

// SetSessionCache is called during startup before the handler serves requests.
func (h *Handler) SetSessionCache(cache sessions.Cache) {
	h.sessionCache = cache
	h.sessions.SetCache(cache)
}

func New(db *sql.DB, origin string, secure bool, internalSecret string, userURL string) (*Handler, error) {
	parsed, err := url.Parse(origin)

	if err != nil || parsed == nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("invalid allowed origin")
	}

	if !secure && parsed.Hostname() != "localhost" && parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "::1" {
		return nil, errors.New("insecure cookies are permitted only for localhost development")
	}

	if secure && parsed.Scheme != "https" {
		return nil, errors.New("secure cookies require an HTTPS origin")
	}

	if len(internalSecret) < 32 {
		return nil, errors.New("internal secret must be at least 32 bytes")
	}

	userService, err := url.Parse(userURL)

	if err != nil || userService == nil || (userService.Scheme != "http" && userService.Scheme != "https") || userService.Host == "" || userService.User != nil || (userService.Path != "" && userService.Path != "/") || userService.RawQuery != "" || userService.Fragment != "" {
		return nil, errors.New("invalid user service URL")
	}

	userHost := userService.Hostname()
	userIP := net.ParseIP(userHost)

	if userService.Scheme == "http" && userHost != "localhost" && (userIP == nil || !userIP.IsLoopback()) {
		return nil, errors.New("remote user service requires HTTPS")
	}

	name := "__Host-mtls_session"

	if !secure {
		name = "mtls_session"
	}

	transport, err := (sharedconfig.ServiceTLS{}).ClientTransport(userURL)

	if err != nil {
		return nil, err
	}

	return &Handler{db: db, credentials: credentials.NewStore(db), sessions: sessions.NewStore(db), origin: origin, secure: secure, cookieName: name, internalSecret: internalSecret, userServiceSecret: internalSecret, rateLimitSecret: internalSecret, userURL: strings.TrimRight(userURL, "/"), client: &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (h *Handler) ConfigureSecretRotation(previous, rateLimitSecret string) error {
	if previous != "" && (len(previous) < 32 || previous == h.internalSecret || previous == h.userServiceSecret) {
		return errors.New("invalid previous internal credential")
	}

	if rateLimitSecret != "" && (len(rateLimitSecret) < 32 || rateLimitSecret == h.internalSecret || rateLimitSecret == h.userServiceSecret || rateLimitSecret == previous) {
		return errors.New("rate-limit credential must be independent and at least 32 bytes")
	}

	h.previousInternalSecret = previous

	if rateLimitSecret != "" {
		h.rateLimitSecret = rateLimitSecret
	}

	return nil
}

func (h *Handler) authorizedInternal(r *http.Request) bool {
	provided := []byte(r.Header.Get("X-Internal-Secret"))
	valid := subtle.ConstantTimeCompare(provided, []byte(h.internalSecret))

	if h.previousInternalSecret != "" {
		valid |= subtle.ConstantTimeCompare(provided, []byte(h.previousInternalSecret))
	}

	return valid == 1
}

func (h *Handler) SetUserServiceSecret(secret string) error {
	if len(secret) < 32 {
		return errors.New("user service credential must be at least 32 bytes")
	}

	h.userServiceSecret = secret
	return nil
}

func (h *Handler) ConfigureInternalTLS(transport *http.Transport, peerClientURI string) {
	h.client.Transport = transport
	h.peerClientURI = peerClientURI
}

// LoadPasswordBlocklist is called at startup, before serving requests.
func (h *Handler) LoadPasswordBlocklist(path string) error {
	return h.credentials.LoadPasswordBlocklist(path)
}

// SetPasswordNormalization is called at startup before serving requests.
func (h *Handler) SetPasswordNormalization(enabled bool) {
	h.credentials.SetPasswordNormalization(enabled)
}

// SetRecoveryMode is called at startup before serving requests.
func (h *Handler) SetRecoveryMode(enabled bool) {
	h.recoveryMode = enabled
}

func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", h.health)
	mux.HandleFunc("GET /ready", h.ready)
	mux.HandleFunc("GET /internal/health", h.internalHealth)
	mux.HandleFunc("GET /internal/metrics", h.internalMetrics)
	mux.HandleFunc("GET /internal/session/moderator", h.internalContentModerator)
	mux.HandleFunc("GET /internal/session/ad-operator", h.internalAdOperator)
	mux.HandleFunc("GET /internal/session", h.internalSession)
	mux.HandleFunc("GET /internal/users/{id}/presence", h.internalPresence)
	mux.HandleFunc("GET /internal/users/active", h.internalActiveUsers)
	mux.HandleFunc("POST /api/auth/login", h.login)
	mux.HandleFunc("POST /api/auth/register", h.register)
	mux.HandleFunc("POST /api/auth/register/resend", h.resendRegistration)
	mux.HandleFunc("POST /api/auth/confirm-email", h.confirmEmail)
	mux.HandleFunc("POST /api/auth/password-reset/request", h.requestPasswordReset)
	mux.HandleFunc("POST /api/auth/password-reset/confirm", h.confirmPasswordReset)
	mux.HandleFunc("POST /api/auth/verify-email/request", h.requestEmailVerification)
	mux.HandleFunc("POST /api/auth/verify-email/confirm", h.confirmEmailVerification)
	mux.HandleFunc("POST /api/auth/email-change/request", h.changeEmail)
	mux.HandleFunc("POST /api/auth/email-change/confirm", h.changeEmail)
	mux.HandleFunc("POST /api/auth/account/delete", h.deleteAccount)
	mux.HandleFunc("POST /api/auth/account/restore", h.restoreAccount)
	mux.HandleFunc("POST /api/auth/moderation/users/{id}/restore", h.moderatorRestoreAccount)
	mux.HandleFunc("POST /api/auth/logout", h.logout)
	mux.HandleFunc("POST /api/auth/password", h.changePassword)
	mux.HandleFunc("POST /api/auth/heartbeat", h.heartbeat)
	mux.HandleFunc("GET /api/auth/sessions", h.listSessions)
	mux.HandleFunc("POST /api/auth/sessions/revoke-others", h.revokeOthers)
	mux.HandleFunc("POST /api/auth/sessions/{id}/revoke", h.revokeSession)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")

		if h.recoveryMode && (r.Method != http.MethodGet || r.URL.Path != "/health") {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}

		if h.peerClientURI != "" && strings.HasPrefix(r.URL.Path, "/internal/") && !sharedconfig.MatchesClientURI(r.TLS, h.peerClientURI) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if r.Method != http.MethodGet && r.Header.Get("Origin") != h.origin {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()

		mux.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	sharedhealth.Database(w, r, h.db)
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Identifier    string `json:"identifier"`
		Password      string `json:"password"`
		DeviceName    string `json:"device_name"`
		RecoveryToken string `json:"recovery_token"`
	}

	if err := decodeJSON(w, r, &request); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if len(request.Identifier) > 254 || len(request.Password) > 1024 || len(request.DeviceName) > 512 {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)

	if err != nil || net.ParseIP(ip) == nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	ipAllowed, accountAllowed, err := h.checkLoginLimits(r, ip, request.Identifier)

	if err != nil {
		log.Printf("login limiter: %v", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	if !ipAllowed || (!accountAllowed && request.RecoveryToken == "") {
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}

	ctx, cancel := contextWithTimeout(r, 10*time.Second)
	defer cancel()

	var recoveryProof *[32]byte

	if request.RecoveryToken != "" {
		hash, valid, err := h.credentials.CheckRecoveryLoginProof(ctx, request.Identifier, request.RecoveryToken)

		if err != nil {
			log.Printf("check recovery login proof: %v", err)
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}

		if !valid {
			if !accountAllowed {
				http.Error(w, "too many attempts", http.StatusTooManyRequests)
			} else {
				http.Error(w, "invalid credentials", http.StatusUnauthorized)
			}

			return
		}

		recoveryProof = &hash
	}

	userID, revision, err := h.credentials.Verify(ctx, request.Identifier, request.Password)

	if errors.Is(err, credentials.ErrInvalidCredentials) {
		if !accountAllowed {
			http.Error(w, "too many attempts", http.StatusTooManyRequests)
		} else {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
		}

		return
	}

	if err != nil {
		log.Printf("verify credentials: %v", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	active, err := h.userExists(ctx, userID)

	if err != nil {
		log.Printf("check user: %v", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	if !active {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	var token string

	if recoveryProof != nil {
		token, err = h.sessions.CreateWithRecovery(ctx, userID, revision, request.DeviceName, *recoveryProof)
	} else {
		token, err = h.sessions.Create(ctx, userID, revision, request.DeviceName)
	}

	if errors.Is(err, sessions.ErrInvalidSession) {
		if !accountAllowed {
			http.Error(w, "too many attempts", http.StatusTooManyRequests)
		} else {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
		}

		return
	}

	if errors.Is(err, sessions.ErrInvalidDevice) {
		http.Error(w, "invalid device name", http.StatusBadRequest)
		return
	}

	if err != nil {
		log.Printf("create session: %v", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	http.SetCookie(w, &http.Cookie{Name: h.cookieName, Value: token, Path: "/", HttpOnly: true, Secure: h.secure, SameSite: http.SameSiteStrictMode, MaxAge: 30 * 24 * 60 * 60})
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) identity(r *http.Request) (sessions.Identity, error) {
	cookies := r.CookiesNamed(h.cookieName)
	if len(cookies) != 1 {
		return sessions.Identity{}, sessions.ErrInvalidSession
	}

	return h.sessions.Authenticate(r.Context(), cookies[0].Value)
}

func (h *Handler) authenticate(w http.ResponseWriter, r *http.Request) (sessions.Identity, bool) {
	identity, err := h.identity(r)

	if errors.Is(err, sessions.ErrInvalidSession) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return sessions.Identity{}, false
	}

	if err != nil {
		log.Printf("session authentication: %v", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return sessions.Identity{}, false
	}

	active, err := h.userExists(r.Context(), identity.UserID)

	if err != nil {
		log.Printf("check user: %v", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return sessions.Identity{}, false
	}

	if !active {
		if err := h.sessions.RevokeAll(r.Context(), identity.UserID); err != nil {
			log.Printf("revoke sessions for inactive user: %v", err)
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return sessions.Identity{}, false
		}

		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return sessions.Identity{}, false
	}

	return identity, true
}

func (h *Handler) heartbeat(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authenticate(w, r); !ok {
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) listSessions(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.authenticate(w, r)

	if !ok {
		return
	}

	offset := 0

	if value := r.URL.Query().Get("offset"); value != "" {
		var err error
		offset, err = strconv.Atoi(value)

		if err != nil || offset < 0 || offset > 10000 {
			http.Error(w, "invalid offset", http.StatusBadRequest)
			return
		}
	}

	list, more, err := h.sessions.List(r.Context(), identity, offset)

	if errors.Is(err, sessions.ErrInvalidSession) {
		h.clearCookie(w)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if err != nil {
		log.Printf("list sessions: %v", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Sessions []sessions.Session `json:"sessions"`
		HasMore  bool               `json:"has_more"`
	}{list, more})
}

func (h *Handler) revokeSession(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.authenticate(w, r)

	if !ok {
		return
	}

	id, err := uuid.Parse(r.PathValue("id"))

	if err != nil {
		http.Error(w, "invalid session id", http.StatusBadRequest)
		return
	}

	if err := h.sessions.Revoke(r.Context(), identity, id); errors.Is(err, sessions.ErrInvalidSession) {
		h.clearCookie(w)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	} else if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	} else if err != nil {
		log.Printf("revoke session: %v", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	if id == identity.SessionID {
		h.clearCookie(w)
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) revokeOthers(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.authenticate(w, r)

	if !ok {
		return
	}

	if err := h.sessions.RevokeOthers(r.Context(), identity); err != nil {
		if errors.Is(err, sessions.ErrInvalidSession) {
			h.clearCookie(w)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		log.Printf("revoke other sessions: %v", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) changePassword(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.authenticate(w, r)

	if !ok {
		return
	}

	var request struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
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

	allowed, err := h.allowLogin(r, ip, identity.UserID.String())

	if err != nil {
		log.Printf("password change limiter: %v", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	if !allowed {
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}

	token, err := h.credentials.ChangePassword(r.Context(), identity.UserID, identity.SessionID, identity.TokenHash, request.CurrentPassword, request.NewPassword)

	if errors.Is(err, credentials.ErrInvalidCredentials) {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	if errors.Is(err, credentials.ErrInvalidPassword) {
		http.Error(w, "invalid new password", http.StatusBadRequest)
		return
	}

	if err != nil {
		log.Printf("change password: %v", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	http.SetCookie(w, &http.Cookie{Name: h.cookieName, Value: token, Path: "/", HttpOnly: true, Secure: h.secure, SameSite: http.SameSiteStrictMode, MaxAge: 30 * 24 * 60 * 60})
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.authenticate(w, r)

	if !ok {
		return
	}

	if err := h.sessions.Revoke(r.Context(), identity, identity.SessionID); err != nil {
		if errors.Is(err, sessions.ErrInvalidSession) {
			h.clearCookie(w)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		log.Printf("logout: %v", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	h.clearCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: h.cookieName, Path: "/", HttpOnly: true, Secure: h.secure, SameSite: http.SameSiteStrictMode, MaxAge: -1})
}

// internalSession only accepts requests authenticated as another backend service.
func (h *Handler) internalSession(w http.ResponseWriter, r *http.Request) {
	if !h.authorizedInternal(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	identity, ok := h.authenticate(w, r)

	if !ok {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		UserID    uuid.UUID `json:"user_id"`
		SessionID uuid.UUID `json:"session_id"`
	}{identity.UserID, identity.SessionID})
}

func (h *Handler) internalActiveUsers(w http.ResponseWriter, r *http.Request) {
	if !h.authorizedInternal(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	ids := r.URL.Query()["id"]
	if len(ids) == 0 || len(ids) > 50 {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	for _, raw := range ids {
		id, err := uuid.Parse(raw)
		if err != nil || id == uuid.Nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
	}

	const query = `SELECT c.user_id FROM credentials AS c
		WHERE c.user_id = ANY($1::uuid[]) AND c.enabled
		AND NOT EXISTS (SELECT 1 FROM account_deletions AS d WHERE d.user_id = c.user_id)`
	rows, err := h.db.QueryContext(r.Context(), query, pq.Array(ids))
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	defer rows.Close()

	active := make([]uuid.UUID, 0, len(ids))
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		active = append(active, id)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(active)
}

func (h *Handler) internalPresence(w http.ResponseWriter, r *http.Request) {
	if !h.authorizedInternal(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	id, err := uuid.Parse(r.PathValue("id"))

	if err != nil {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}

	presence, err := h.sessions.UserPresence(r.Context(), id)

	if err != nil {
		log.Printf("session presence: %v", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(presence)
}

func (h *Handler) userExists(ctx context.Context, userID uuid.UUID) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.userURL+"/internal/users/"+userID.String()+"/exists", nil)

	if err != nil {
		return false, errors.New("cannot construct user service request")
	}

	req.Header.Set("X-Internal-Secret", h.userServiceSecret)
	resp, err := h.doPeerRequest(req)

	if err != nil {
		return false, peerRequestError(err)
	}

	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, errors.New("user service returned an unexpected status")
	}
}
