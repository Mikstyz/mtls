package httpapi

import (
	"bytes"
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	sharedconfig "mtls/shared/config"
	sharedhealth "mtls/shared/health"
	"mtls/user/internal/models"
	"mtls/user/internal/repositories"
)

type UserRepository interface {
	ProfileImages(context.Context, uuid.UUID) (models.ProfileImages, error)
	ChangeProfileImage(context.Context, uuid.UUID, string, *uuid.UUID) error
	ProfileImageHistory(context.Context, uuid.UUID, int64) ([]models.ProfileImageChange, error)
	ReportProfileImage(context.Context, uuid.UUID, uuid.UUID, models.ProfileImageReport) (int, error)
	ProfileImageModerationQueue(context.Context, uuid.UUID) ([]models.ProfileImageCase, error)
	ProfileModerationMediaOwner(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (uuid.UUID, error)
	DecideProfileImageReport(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, string) (int, error)
	ProfileImageNotices(context.Context, uuid.UUID) ([]models.ProfileImageNotice, error)
	ProfileImageAppeals(context.Context, uuid.UUID) ([]models.ProfileImageAppeal, error)
	SubmitProfileImageAppeal(context.Context, uuid.UUID, uuid.UUID, string) (int, error)
	ReviewProfileImageAppeal(context.Context, uuid.UUID, uuid.UUID, string) (int, error)
	OwnProfileImageReport(context.Context, uuid.UUID, uuid.UUID) (models.ProfileImageReport, error)
	NextMediaPurge(context.Context) (uuid.UUID, error)
	FinishMediaPurge(context.Context, uuid.UUID) error
	MediaAccessOwner(context.Context, uuid.UUID, uuid.UUID, bool) (uuid.UUID, string, *int64, bool, error)
	PlaybackSettings(context.Context, uuid.UUID) (models.PlaybackSettings, error)
	SetPlaybackSettings(context.Context, uuid.UUID, models.PlaybackSettings) error
	SearchCandidates(context.Context, []uuid.UUID, string, string) ([]models.SearchUser, error)
	ReserveMedia(context.Context, uuid.UUID, uuid.UUID) error
	MarkMediaReady(context.Context, uuid.UUID, uuid.UUID, string, *int64) error
	ReadyMediaKind(context.Context, uuid.UUID, uuid.UUID) (string, error)
	RevokeMedia(context.Context, uuid.UUID, uuid.UUID) error
	ExistingProfiles(context.Context, []uuid.UUID) ([]uuid.UUID, error)
	GetById(context.Context, uuid.UUID) (*models.User, error)
	UpdateUser(context.Context, models.User) error
	UpdatePresenceVisibility(context.Context, uuid.UUID, string) error
	RecordPresence(context.Context, uuid.UUID, uuid.UUID) error
	ProvisionUser(context.Context, uuid.UUID, string, time.Time) error
	ApplyAccountLifecycle(context.Context, uuid.UUID, uuid.UUID, string, time.Time) error
}

type Handler struct {
	db                  *sql.DB
	users               UserRepository
	authURL             string
	searchURL           string
	searchSecret        string
	contentSearchURL    string
	contentSearchSecret string
	contentClientURI    string
	publicationSecret   string
	secret              string
	previousSecret      string
	authServiceSecret   string
	cookieName          string
	origin              string
	client              *http.Client
	recoveryMode        bool
	peerRequests        atomic.Uint64
	peerFailures        atomic.Uint64
	peerClientURI       string
	mediaSecret         string
	previousMediaSecret string
	mediaClientURI      string
}

type identity struct {
	UserID    uuid.UUID `json:"user_id"`
	SessionID uuid.UUID `json:"session_id"`
}

func New(db *sql.DB, users UserRepository, authURL, secret, cookieName, origin string) (*Handler, error) {
	parsed, err := url.Parse(authURL)

	if err != nil || parsed == nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("invalid auth service URL")
	}

	host := parsed.Hostname()
	ip := net.ParseIP(host)

	if parsed.Scheme == "http" && host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return nil, errors.New("remote auth service requires HTTPS")
	}

	if len(secret) < 32 || (cookieName != "__Host-mtls_session" && cookieName != "mtls_session") {
		return nil, errors.New("invalid internal secret or cookie name")
	}

	allowedOrigin, err := url.Parse(origin)

	if err != nil || allowedOrigin == nil || (allowedOrigin.Scheme != "http" && allowedOrigin.Scheme != "https") || allowedOrigin.Host == "" || allowedOrigin.User != nil || allowedOrigin.Path != "" || allowedOrigin.RawQuery != "" || allowedOrigin.Fragment != "" {
		return nil, errors.New("invalid allowed origin")
	}

	transport, err := (sharedconfig.ServiceTLS{}).ClientTransport(authURL)

	if err != nil {
		return nil, err
	}

	return &Handler{db: db, users: users, authURL: strings.TrimRight(authURL, "/"), secret: secret, authServiceSecret: secret, cookieName: cookieName, origin: origin,
		client: &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (h *Handler) SetAuthServiceSecret(secret string) error {
	if len(secret) < 32 {
		return errors.New("auth service credential must be at least 32 bytes")
	}

	h.authServiceSecret = secret
	return nil
}

func (h *Handler) SetPreviousInternalSecret(previous string) error {
	if previous != "" && (len(previous) < 32 || previous == h.secret || previous == h.authServiceSecret) {
		return errors.New("invalid previous internal credential")
	}

	h.previousSecret = previous
	return nil
}

func (h *Handler) authorizedInternal(r *http.Request) bool {
	provided := []byte(r.Header.Get("X-Internal-Secret"))
	valid := subtle.ConstantTimeCompare(provided, []byte(h.secret))

	if h.previousSecret != "" {
		valid |= subtle.ConstantTimeCompare(provided, []byte(h.previousSecret))
	}

	return valid == 1
}

func (h *Handler) ConfigureInternalTLS(transport *http.Transport, peerClientURI string) {
	h.client.Transport = transport
	h.peerClientURI = peerClientURI
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
	mux.HandleFunc("GET "+scheduledPublicationCheckPath, h.scheduledPublicationCheck)
	mux.HandleFunc("GET /internal/users/{id}/exists", h.internalUserExists)
	mux.HandleFunc("PUT /internal/users/{id}", h.internalProvisionUser)
	mux.HandleFunc("PUT /internal/users/{id}/lifecycle/{operation}", h.internalAccountLifecycle)
	mux.HandleFunc("GET /api/users/media/{id}/access", h.mediaAccess)
	mux.HandleFunc("GET /api/users/media/{id}/covers/{cover_post}/access", h.mediaAccess)
	mux.HandleFunc("GET /api/users/media/{id}/posts/{post}/access", h.mediaAccess)
	mux.HandleFunc("GET /api/users/{id}/access", h.accountAccess)
	mux.HandleFunc("GET /api/users/accounts/active", h.activeAccountsForViewer)
	mux.HandleFunc("GET /api/users/{id}/profile", h.publicProfile)
	mux.HandleFunc("GET /api/users/{id}/profile/media/{media}/access", h.profileImageAccess)
	mux.HandleFunc("GET /api/users/me/profile-images/history", h.profileImageHistory)
	mux.HandleFunc("PUT /api/users/me/profile-image-reports/{report}", h.profileImageReport)
	mux.HandleFunc("GET /api/users/me/profile-image-reports/{report}", h.profileImageReport)
	mux.HandleFunc("GET /api/users/me/moderation/profile-image-reports", h.profileImageModeration)
	mux.HandleFunc("PUT /api/users/me/moderation/profile-image-reports/{case}", h.profileImageModeration)
	mux.HandleFunc("GET /api/users/me/profile-image-moderation/notices", h.profileImageOwnerModeration)
	mux.HandleFunc("PUT /api/users/me/profile-image-moderation/appeals/{case}", h.profileImageOwnerModeration)
	mux.HandleFunc("GET /api/users/me/moderation/profile-image-appeals", h.profileImageAppealModeration)
	mux.HandleFunc("PUT /api/users/me/moderation/profile-image-appeals/{case}", h.profileImageAppealModeration)
	mux.HandleFunc("PUT /api/users/me/profile-images/{slot}", h.changeProfileImage)
	mux.HandleFunc("DELETE /api/users/me/profile-images/{slot}", h.changeProfileImage)
	mux.HandleFunc("GET /api/users/media/{id}/ownership", h.mediaOwnership)
	mux.HandleFunc("GET /api/users/media/{id}/moderation/{case}/access", h.moderationMediaAccess)
	mux.HandleFunc("GET /api/users/media/{id}/profile-moderation/{case}/access", h.profileModerationMediaAccess)
	mux.HandleFunc("POST /internal/media/owner-purges/next", h.nextMediaPurge)
	mux.HandleFunc("PUT /internal/media/owner-purges/{owner}/complete", h.finishMediaPurge)
	mux.HandleFunc("PUT /internal/media/{id}/reservation", h.reserveMedia)
	mux.HandleFunc("PUT /internal/media/{id}/ready", h.markMediaReady)
	mux.HandleFunc("PUT /internal/media/{id}/revoke", h.revokeMedia)
	mux.HandleFunc("GET /api/users/search", h.searchUsers)
	mux.HandleFunc("GET /api/users/search/content", h.searchContent)
	mux.HandleFunc("GET /api/users/feed", h.feed)
	mux.HandleFunc("GET /api/users/me/participation", h.participant)
	mux.HandleFunc("GET /api/users/me/moderator", h.contentModerator)
	mux.HandleFunc("GET /api/users/me/ad-operator", h.adOperator)
	mux.HandleFunc("GET /api/users/me", h.me)
	mux.HandleFunc("PATCH /api/users/me", h.updateMe)
	mux.HandleFunc("GET /api/users/me/playback", h.playbackSettings)
	mux.HandleFunc("PUT /api/users/me/playback", h.playbackSettings)
	mux.HandleFunc("PATCH /api/users/me/privacy", h.updatePrivacy)
	mux.HandleFunc("POST /api/users/heartbeat", h.heartbeat)
	mux.HandleFunc("GET /api/users/{id}/presence", h.presence)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")

		if h.recoveryMode && (r.Method != http.MethodGet || r.URL.Path != "/health") {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}

		mediaPath := strings.HasPrefix(r.URL.Path, "/internal/media/")
		contentPeerPath := h.contentClientURI != "" && r.Method == http.MethodGet && r.URL.Path == scheduledPublicationCheckPath

		if mediaPath {
			if h.mediaSecret == "" || !h.authorizedMedia(r) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			if h.mediaClientURI != "" {
				if !sharedconfig.MatchesClientURI(r.TLS, h.mediaClientURI) {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
			} else {
				host, _, err := net.SplitHostPort(r.RemoteAddr)
				ip := net.ParseIP(host)

				if err != nil || ip == nil || !ip.IsLoopback() {
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
			}
		} else if !contentPeerPath && h.peerClientURI != "" && strings.HasPrefix(r.URL.Path, "/internal/") &&
			!sharedconfig.MatchesClientURI(r.TLS, h.peerClientURI) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		internalProvision := r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/internal/users/") && h.authorizedInternal(r)
		internalMedia := mediaPath && h.authorizedMedia(r)

		if r.Method != http.MethodGet && !internalProvision && !internalMedia && r.Header.Get("Origin") != h.origin {
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

func (h *Handler) authenticate(w http.ResponseWriter, r *http.Request) (identity, bool) {
	return h.authenticateSession(w, r, "/internal/session")
}

func (h *Handler) authenticateSession(w http.ResponseWriter, r *http.Request, path string) (identity, bool) {
	cookies := r.CookiesNamed(h.cookieName)
	if len(cookies) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return identity{}, false
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, h.authURL+path, nil)

	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return identity{}, false
	}

	req.Header.Set("X-Internal-Secret", h.authServiceSecret)
	req.AddCookie(&http.Cookie{Name: h.cookieName, Value: cookies[0].Value})
	resp, err := h.doPeerRequest(req)

	if err != nil {
		log.Printf("auth service request failed: %v", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return identity{}, false
	}

	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		http.Error(w, "forbidden", http.StatusForbidden)
		return identity{}, false
	}

	if resp.StatusCode == http.StatusUnauthorized {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return identity{}, false
	}

	var result identity

	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&result) != nil || result.UserID == uuid.Nil || result.SessionID == uuid.Nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return identity{}, false
	}

	return result, true
}

func (h *Handler) mediaAccess(w http.ResponseWriter, r *http.Request) {
	h.checkMedia(w, r, false)
}

func (h *Handler) mediaOwnership(w http.ResponseWriter, r *http.Request) {
	h.checkMedia(w, r, true)
}

func (h *Handler) checkMedia(w http.ResponseWriter, r *http.Request, requireOwner bool) {
	id, ok := h.authenticateParticipant(w, r)

	if !ok {
		return
	}

	mediaID, err := uuid.Parse(r.PathValue("id"))

	if err != nil || mediaID == uuid.Nil {
		http.NotFound(w, r)
		return
	}

	var post uuid.UUID
	value := r.PathValue("post")
	cover := r.PathValue("cover_post") != ""
	if cover {
		value = r.PathValue("cover_post")
	}
	if value != "" {
		post, err = uuid.Parse(value)

		if err != nil || post == uuid.Nil {
			http.NotFound(w, r)
			return
		}
	}

	owner, quality, duration, allowed, err := h.users.MediaAccessOwner(r.Context(), mediaID, id.UserID, post != uuid.Nil)

	if err != nil {
		log.Printf("check media access: %v", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	if !allowed || requireOwner && owner != id.UserID {
		http.NotFound(w, r)
		return
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

	if post != uuid.Nil {
		allowed, popular, frame, err := h.checkPostMedia(r.Context(), post, mediaID, owner, id.UserID, cover)

		if err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		if !allowed {
			http.NotFound(w, r)
			return
		}
		if cover && frame != "" {
			w.Header().Set("X-Cover-Frame", frame)
		}
		w.Header().Set("X-Playback-Quality", quality)

		if popular {
			w.Header().Set("X-Playback-Popular", "1")
		}

		w.Header().Set("X-Viewer-ID", id.UserID.String())
	}

	if requireOwner {
		kind, err := h.users.ReadyMediaKind(r.Context(), owner, mediaID)
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		if kind != "" {
			w.Header().Set("X-Media-Kind", kind)
		}
	}

	if duration != nil {
		w.Header().Set("X-Media-Duration-Ms", strconv.FormatInt(*duration, 10))
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) me(w http.ResponseWriter, r *http.Request) {
	id, ok := h.authenticate(w, r)

	if !ok {
		return
	}

	user, err := h.users.GetById(r.Context(), id.UserID)

	if !h.handleUserError(w, err) {
		return
	}

	images, err := h.users.ProfileImages(r.Context(), id.UserID)
	if !h.handleUserError(w, err) {
		return
	}

	writeJSON(w, struct {
		*models.User
		models.ProfileImages
	}{user, images})
}

func (h *Handler) updateMe(w http.ResponseWriter, r *http.Request) {
	id, ok := h.authenticateParticipant(w, r)

	if !ok {
		return
	}

	var body struct {
		Nickname string `json:"nickname"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&body); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if err := decoder.Decode(new(any)); err != io.EOF {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	body.Nickname = strings.TrimSpace(body.Nickname)

	if !validNickname(body.Nickname) {
		http.Error(w, "invalid nickname", http.StatusBadRequest)
		return
	}

	if err := h.users.UpdateUser(r.Context(), models.User{ID: id.UserID, Nickname: body.Nickname}); !h.handleUserError(w, err) {
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func validNickname(nickname string) bool {
	return utf8.ValidString(nickname) && utf8.RuneCountInString(nickname) > 0 && utf8.RuneCountInString(nickname) <= 64 && strings.IndexFunc(nickname, unicode.IsControl) < 0
}

func (h *Handler) internalProvisionUser(w http.ResponseWriter, r *http.Request) {
	if !h.authorizedInternal(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	id, err := uuid.Parse(r.PathValue("id"))

	if err != nil || id == uuid.Nil {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}

	var body struct {
		Nickname   string    `json:"nickname"`
		ValidUntil time.Time `json:"valid_until"`
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&body); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if err := decoder.Decode(new(any)); err != io.EOF {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	body.Nickname = strings.TrimSpace(body.Nickname)

	if !validNickname(body.Nickname) {
		http.Error(w, "invalid nickname", http.StatusBadRequest)
		return
	}

	err = h.users.ProvisionUser(r.Context(), id, body.Nickname, body.ValidUntil)

	if errors.Is(err, repositories.ErrProvisionConflict) {
		http.Error(w, "conflicting registration", http.StatusConflict)
		return
	}

	if !h.handleUserError(w, err) {
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) heartbeat(w http.ResponseWriter, r *http.Request) {
	id, ok := h.authenticateParticipant(w, r)

	if !ok {
		return
	}

	if err := h.users.RecordPresence(r.Context(), id.UserID, id.SessionID); !h.handleUserError(w, err) {
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) presence(w http.ResponseWriter, r *http.Request) {
	requester, ok := h.authenticateParticipant(w, r)

	if !ok {
		return
	}

	userID, err := uuid.Parse(r.PathValue("id"))

	if err != nil {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}

	user, err := h.users.GetById(r.Context(), userID)

	if !h.handleUserError(w, err) {
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, h.authURL+"/internal/users/"+userID.String()+"/presence", nil)

	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	req.Header.Set("X-Internal-Secret", h.authServiceSecret)
	resp, err := h.doPeerRequest(req)

	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	defer resp.Body.Close()

	var result struct {
		Active     *bool      `json:"active,omitempty"`
		Visible    bool       `json:"visible"`
		Online     bool       `json:"online"`
		LastOnline *time.Time `json:"last_online"`
	}

	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&result) != nil || result.Active == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	if !*result.Active {
		http.NotFound(w, r)
		return
	}

	if user.PresenceVisibility == "nobody" && requester.UserID != userID {
		writeJSON(w, struct {
			Visible bool `json:"visible"`
		}{Visible: false})
		return
	}

	if result.LastOnline == nil || (user.LastOnline != nil && user.LastOnline.After(*result.LastOnline)) {
		result.LastOnline = user.LastOnline
	}

	result.Visible = true
	result.Active = nil

	writeJSON(w, result)
}

func (h *Handler) handleUserError(w http.ResponseWriter, err error) bool {
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "not found", http.StatusNotFound)
		return false
	}

	if err != nil {
		log.Printf("user repository: %v", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return false
	}

	return true
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	var buffer bytes.Buffer

	if err := json.NewEncoder(&buffer).Encode(value); err != nil {
		http.Error(w, "response error", http.StatusInternalServerError)
		return
	}

	_, _ = w.Write(buffer.Bytes())
}

func (h *Handler) internalUserExists(w http.ResponseWriter, r *http.Request) {
	if !h.authorizedInternal(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	id, err := uuid.Parse(r.PathValue("id"))

	if err != nil {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}

	_, err = h.users.GetById(r.Context(), id)

	if !h.handleUserError(w, err) {
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
