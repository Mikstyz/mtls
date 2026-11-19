package httpapi

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"mtls/content/internal/catalog"
)

type Catalog interface {
	AllowsPostMedia(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID) (bool, error)
	DraftForPublication(context.Context, uuid.UUID, uuid.UUID, int64) (catalog.PublicationDraft, error)
	PublishPost(context.Context, uuid.UUID, uuid.UUID, int64, string) (int64, error)
	PublishedPostForViewer(context.Context, uuid.UUID, uuid.UUID) (catalog.PublishedPost, error)
	ViewablePostAuthor(context.Context, uuid.UUID, uuid.UUID) (uuid.UUID, error)
	CountPostView(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, int32) error
	SetReaction(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, string, bool) error
	ListFavorites(context.Context, uuid.UUID, int, *catalog.FavoriteCursor) ([]catalog.Favorite, error)
	ChangeAuthorRemoval(context.Context, uuid.UUID, uuid.UUID, int64, bool) (int64, error)
	ListPublic(context.Context, catalog.Filter) ([]catalog.FeedPost, error)
	RecheckPublicSearch(context.Context, []uuid.UUID, string) ([]catalog.PublicSearchCandidate, error)
	CreateDraft(context.Context, catalog.Draft) (uuid.UUID, error)
	ListDrafts(context.Context, uuid.UUID, int, *catalog.DraftCursor) ([]catalog.DraftSummary, error)
	EditDraft(context.Context, uuid.UUID, uuid.UUID, int64, string, string) (int64, error)
	SetDraftMedia(context.Context, uuid.UUID, uuid.UUID, int64, []uuid.UUID) (int64, error)
}

type Purger interface {
	PurgeAuthor(context.Context, uuid.UUID) error
}

type Handler struct {
	catalog             Catalog
	purger              Purger
	secret              string
	previousSecret      string
	user                *userClient
	purgeSecret         string
	previousPurgeSecret string
	mediaViewSecret     string
}

func New(store Catalog, secret, previous string) (http.Handler, error) {
	return newHandler(store, nil, secret, previous, nil, "", "", "")
}

func NewWithUser(store Catalog, secret, previous, address, cookieName string) (http.Handler, error) {
	return NewConfigured(store, nil, secret, previous, address, cookieName, "", "", "")
}

func NewConfigured(store Catalog, purger Purger, secret, previous, address, cookieName, purgeSecret, previousPurgeSecret, mediaViewSecret string) (http.Handler, error) {
	var user *userClient

	if address != "" || cookieName != "" {
		var err error
		user, err = newUserClient(address, cookieName)

		if err != nil {
			return nil, err
		}
	}

	return newHandler(store, purger, secret, previous, user, purgeSecret, previousPurgeSecret, mediaViewSecret)
}

func newHandler(store Catalog, purger Purger, secret, previous string, user *userClient, purgeSecret, previousPurgeSecret, mediaViewSecret string) (http.Handler, error) {
	valid := func(value string) bool {
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

	if store == nil || !valid(secret) || (previous != "" && (!valid(previous) || previous == secret)) {
		return nil, errors.New("invalid content service configuration")
	}

	keys := []string{secret, previous, purgeSecret, previousPurgeSecret, mediaViewSecret}

	for i, key := range keys {
		if i >= 2 && key != "" && !valid(key) {
			return nil, errors.New("invalid content service credential")
		}

		for _, other := range keys[i+1:] {
			if key != "" && key == other {
				return nil, errors.New("content credentials must be distinct")
			}
		}
	}

	if (purgeSecret == "") != (purger == nil) {
		return nil, errors.New("purge credential and database must be configured together")
	}

	if purgeSecret == "" && previousPurgeSecret != "" {
		return nil, errors.New("previous purge credential requires a current credential")
	}

	h := &Handler{catalog: store, purger: purger, secret: secret, previousSecret: previous, user: user, purgeSecret: purgeSecret, previousPurgeSecret: previousPurgeSecret}
	h.mediaViewSecret = mediaViewSecret
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /internal/feed", h.feedCandidates)
	mux.HandleFunc("GET /internal/feed/posts", h.feedPosts)
	mux.HandleFunc("POST /internal/search/recheck", h.recheckSearch)
	mux.HandleFunc("POST /internal/drafts", h.createDraft)
	mux.HandleFunc("GET /internal/drafts", h.listDrafts)
	mux.HandleFunc("PUT /internal/drafts/{id}", h.editDraft)
	mux.HandleFunc("PUT /internal/drafts/{id}/media", h.setDraftMedia)
	mux.HandleFunc("POST /internal/drafts/{id}/publish", h.publishDraft)
	mux.HandleFunc("GET /internal/posts/{id}", h.viewPublishedPost)
	mux.HandleFunc("PUT /internal/posts/{id}/like", h.setLike)
	mux.HandleFunc("DELETE /internal/posts/{id}/like", h.setLike)
	mux.HandleFunc("PUT /internal/posts/{id}/favorite", h.setFavorite)
	mux.HandleFunc("DELETE /internal/posts/{id}/favorite", h.setFavorite)
	mux.HandleFunc("GET /internal/favorites", h.favorites)
	mux.HandleFunc("GET /internal/posts/{id}/media/{media}/access", h.postMediaAccess)
	mux.HandleFunc("POST /internal/posts/{id}/media/{media}/view", h.recordMediaView)
	mux.HandleFunc("POST /internal/posts/{id}/remove", h.removeOwnPost)
	mux.HandleFunc("POST /internal/posts/{id}/restore", h.restoreOwnPost)
	mux.HandleFunc("DELETE /internal/users/{id}/content", h.purgeAuthor)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "private, no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(w, r)
	}), nil
}

func (h *Handler) authorized(r *http.Request) bool {
	values := r.Header.Values("X-Internal-Secret")

	if len(values) != 1 {
		return false
	}

	valid := subtle.ConstantTimeCompare([]byte(values[0]), []byte(h.secret))

	if h.previousSecret != "" {
		valid |= subtle.ConstantTimeCompare([]byte(values[0]), []byte(h.previousSecret))
	}

	return valid == 1
}

func (h *Handler) authorizedPurge(r *http.Request) bool {
	values := r.Header.Values("X-Internal-Secret")

	if len(values) != 1 || h.purgeSecret == "" {
		return false
	}

	valid := subtle.ConstantTimeCompare([]byte(values[0]), []byte(h.purgeSecret))

	if h.previousPurgeSecret != "" {
		valid |= subtle.ConstantTimeCompare([]byte(values[0]), []byte(h.previousPurgeSecret))
	}

	return valid == 1
}
