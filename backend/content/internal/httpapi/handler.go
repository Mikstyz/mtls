package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"mtls/content/internal/catalog"
	sharedconfig "mtls/shared/config"
)

type Catalog interface {
	RevokeMediaAttachment(context.Context, uuid.UUID, uuid.UUID) (bool, error)
	AdCampaignDailyReport(context.Context, uuid.UUID, time.Time, time.Time) ([]catalog.AdCampaignDay, error)
	SubmitAnonymousSafetyReport(context.Context, uuid.UUID, string) (bool, error)
	ApplyProfilePointsEvent(context.Context, uuid.UUID, uuid.UUID, string, string) (bool, error)
	EditPublishedPost(context.Context, uuid.UUID, uuid.UUID, int64, string, string) (int64, error)
	OwnerLibrary(context.Context, uuid.UUID, string, int, *catalog.DraftCursor) ([]catalog.OwnerPost, error)
	SchedulePost(context.Context, uuid.UUID, uuid.UUID, int64, *time.Time, string) (int, error)
	ParticipationBanned(context.Context, uuid.UUID) (bool, error)
	Points(context.Context, uuid.UUID) (catalog.ModerationPoints, error)
	ModerationNotices(context.Context, uuid.UUID) ([]catalog.ModerationNotice, error)
	AppealQueue(context.Context, uuid.UUID) ([]catalog.PendingAppeal, error)
	AppealDetail(context.Context, uuid.UUID, uuid.UUID) (json.RawMessage, error)
	SubmitAppeal(context.Context, uuid.UUID, uuid.UUID, string) (int, error)
	ReviewAppeal(context.Context, uuid.UUID, uuid.UUID, string) (int, error)
	ModerationQueue(context.Context, uuid.UUID, *catalog.ModerationQueueCursor) ([]catalog.ModerationCase, error)
	ModerationCaseDetail(context.Context, uuid.UUID, uuid.UUID, *int64) (json.RawMessage, error)
	AllowsCaseMedia(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID) (bool, error)
	ModerateReport(context.Context, uuid.UUID, uuid.UUID, catalog.ModerationAction) (int64, error)
	SetVideoCover(context.Context, uuid.UUID, uuid.UUID, int64, *uuid.UUID, *string) error
	ReportCommentAuthor(context.Context, uuid.UUID, uuid.UUID) (uuid.UUID, error)
	SubmitReport(context.Context, uuid.UUID, catalog.Report) (string, error)
	OwnReport(context.Context, uuid.UUID, uuid.UUID) (catalog.Report, error)
	PostHistory(context.Context, uuid.UUID, uuid.UUID, int64, int64) ([]catalog.PostHistoryItem, error)
	SelectAd(context.Context, uuid.UUID, uuid.UUID, string) (*catalog.Ad, error)
	ReportAdImpression(context.Context, uuid.UUID, uuid.UUID) (int, error)
	AdCampaigns(context.Context, *uuid.UUID, int) ([]catalog.AdCampaign, error)
	PutAdCampaign(context.Context, uuid.UUID, uuid.UUID, int64, catalog.AdCampaignSettings) (int, error)
	TestOffer(context.Context, uuid.UUID) (catalog.TestOffer, error)
	CreateTestOffer(context.Context, uuid.UUID, uuid.UUID, catalog.TestOffer) error
	BuyTestOffer(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, int64) (int, error)
	RevokeTestOrder(context.Context, uuid.UUID, uuid.UUID) error
	TestReceipt(context.Context, uuid.UUID, uuid.UUID) (catalog.TestReceipt, error)
	TestReceipts(context.Context, uuid.UUID, int, *catalog.TestReceiptCursor) ([]catalog.TestReceipt, error)
	WriteComment(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, *string) (int, error)
	ListComments(context.Context, uuid.UUID, uuid.UUID, int, *time.Time, uuid.UUID) ([]catalog.Comment, error)
	AllowsPostMedia(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID, bool) (bool, bool, string, error)
	DraftForPublication(context.Context, uuid.UUID, uuid.UUID, int64) (catalog.PublicationDraft, error)
	PublishPost(context.Context, uuid.UUID, uuid.UUID, int64, string, *int64) (int64, error)
	PublishedPostForViewer(context.Context, uuid.UUID, uuid.UUID) (catalog.PublishedPost, error)
	ViewablePostAuthor(context.Context, uuid.UUID, uuid.UUID) (uuid.UUID, error)
	CountPostView(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, int32) error
	SetReaction(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, string, bool) error
	ListFavorites(context.Context, uuid.UUID, int, *catalog.FavoriteCursor) ([]catalog.Favorite, error)
	ChangeAuthorRemoval(context.Context, uuid.UUID, uuid.UUID, int64, bool) (int64, error)
	ListPublic(context.Context, catalog.Filter) ([]catalog.FeedPost, error)
	RecheckPublicSearch(context.Context, []uuid.UUID, string, string) ([]catalog.PublicSearchCandidate, error)
	CreateDraft(context.Context, catalog.Draft) (uuid.UUID, error)
	ListDrafts(context.Context, uuid.UUID, int, *catalog.DraftCursor) ([]catalog.DraftSummary, error)
	EditDraft(context.Context, uuid.UUID, uuid.UUID, int64, string, string) (int64, error)
	SetDraftMedia(context.Context, uuid.UUID, uuid.UUID, int64, []uuid.UUID) (int64, error)
}

type Purger interface {
	PurgeAuthor(context.Context, uuid.UUID, bool) error
}

type DeliverySecrets struct {
	ProfilePoints   string
	MediaRevocation string
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
	coverFrames         *coverFrameClient
	deliverySecrets     DeliverySecrets
}

func New(store Catalog, secret, previous string) (http.Handler, error) {
	return newHandler(store, nil, secret, previous, nil, "", "", "", nil, DeliverySecrets{})
}

func NewWithUser(store Catalog, secret, previous, address, cookieName string) (http.Handler, error) {
	return NewConfigured(store, nil, secret, previous, address, cookieName, "", "", "", sharedconfig.ServiceTLS{}, CoverFramePeer{}, DeliverySecrets{})
}

func NewConfigured(store Catalog, purger Purger, secret, previous, address, cookieName, purgeSecret, previousPurgeSecret, mediaViewSecret string, userTLS sharedconfig.ServiceTLS, framePeer CoverFramePeer, deliverySecrets DeliverySecrets) (http.Handler, error) {
	var user *userClient

	if address != "" || cookieName != "" {
		var err error
		user, err = newUserClient(address, cookieName, userTLS)

		if err != nil {
			return nil, err
		}
	}

	coverFrames, err := newCoverFrameClient(framePeer)
	if err != nil {
		return nil, err
	}
	if coverFrames != nil && user == nil {
		return nil, errors.New("cover frames require user service")
	}

	return newHandler(store, purger, secret, previous, user, purgeSecret, previousPurgeSecret, mediaViewSecret, coverFrames, deliverySecrets)
}

func newHandler(store Catalog, purger Purger, secret, previous string, user *userClient, purgeSecret, previousPurgeSecret, mediaViewSecret string, coverFrames *coverFrameClient, deliverySecrets DeliverySecrets) (http.Handler, error) {
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

	keys := []string{secret, previous, purgeSecret, previousPurgeSecret, mediaViewSecret, deliverySecrets.ProfilePoints, deliverySecrets.MediaRevocation}

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
	h.coverFrames = coverFrames
	h.deliverySecrets = deliverySecrets
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /internal/feed", h.feedCandidates)
	mux.HandleFunc("POST /internal/profile-moderation/points", h.profilePointsEvent)
	mux.HandleFunc("POST /internal/media-revocations", h.mediaRevocation)
	mux.HandleFunc("GET /internal/feed/posts", h.feedPosts)
	mux.HandleFunc("POST /internal/search/recheck", h.recheckSearch)
	mux.HandleFunc("POST /internal/drafts", h.createDraft)
	mux.HandleFunc("GET /internal/drafts", h.listDrafts)
	mux.HandleFunc("PUT /internal/drafts/{id}", h.editDraft)
	mux.HandleFunc("PUT /internal/drafts/{id}/media", h.setDraftMedia)
	mux.HandleFunc("PUT /internal/drafts/{id}/schedule", h.schedulePost)
	mux.HandleFunc("POST /internal/drafts/{id}/publish", h.publishDraft)
	mux.HandleFunc("GET /internal/posts/{id}/comments", h.comments)
	mux.HandleFunc("PUT /internal/posts/{id}/comments/{comment}", h.comments)
	mux.HandleFunc("DELETE /internal/posts/{id}/comments/{comment}", h.comments)
	mux.HandleFunc("GET /internal/posts/{id}/history", h.postHistory)
	mux.HandleFunc("GET /internal/me/posts", h.ownerLibrary)
	mux.HandleFunc("GET /internal/me/moderation/points", h.moderationPoints)
	mux.HandleFunc("GET /internal/me/moderation/notices", h.appeals)
	mux.HandleFunc("PUT /internal/me/moderation/appeals/{id}", h.appeals)
	mux.HandleFunc("GET /internal/moderation/appeals", h.appeals)
	mux.HandleFunc("GET /internal/moderation/appeals/{id}", h.appeals)
	mux.HandleFunc("PUT /internal/moderation/appeals/{id}", h.appeals)
	mux.HandleFunc("GET /internal/participation/{id}", h.participation)
	mux.HandleFunc("GET /internal/moderation/cases", h.moderate)
	mux.HandleFunc("GET /internal/moderation/cases/{id}", h.moderate)
	mux.HandleFunc("GET /internal/moderation/cases/{id}/media/{media}/access", h.moderationMediaAccess)
	mux.HandleFunc("PUT /internal/moderation/cases/{id}", h.moderate)
	mux.HandleFunc("PUT /internal/reports/{id}", h.report)
	mux.HandleFunc("GET /internal/reports/{id}", h.report)
	mux.HandleFunc("POST /internal/safety-reports", h.anonymousSafetyReport)
	mux.HandleFunc("PUT /internal/posts/{id}", h.editPublication)
	mux.HandleFunc("GET /internal/posts/{id}", h.viewPublishedPost)
	mux.HandleFunc("PUT /internal/posts/{id}/like", h.setLike)
	mux.HandleFunc("DELETE /internal/posts/{id}/like", h.setLike)
	mux.HandleFunc("PUT /internal/posts/{id}/favorite", h.setFavorite)
	mux.HandleFunc("DELETE /internal/posts/{id}/favorite", h.setFavorite)
	mux.HandleFunc("GET /internal/test-sales/posts/{id}/offer", h.testSales)
	mux.HandleFunc("PUT /internal/test-sales/posts/{id}/offer", h.testSales)
	mux.HandleFunc("PUT /internal/test-sales/posts/{id}/orders/{order}", h.testSales)
	mux.HandleFunc("GET /internal/test-sales/orders/{order}", h.testOrder)
	mux.HandleFunc("GET /internal/test-sales/orders", h.testOrders)
	mux.HandleFunc("DELETE /internal/test-sales/orders/{order}", h.testOrder)
	mux.HandleFunc("PUT /internal/ads/{placement}/{request_id}", h.selectAd)
	mux.HandleFunc("PUT /internal/ads/impressions/{request_id}", h.reportAdImpression)
	mux.HandleFunc("GET /internal/ads/campaigns", h.adCampaigns)
	mux.HandleFunc("GET /internal/ads/campaigns/{id}/report", h.adCampaignReport)
	mux.HandleFunc("PUT /internal/ads/campaigns/{id}", h.adCampaigns)
	mux.HandleFunc("GET /internal/favorites", h.favorites)
	mux.HandleFunc("PUT /internal/posts/{id}/cover", h.setVideoCover)
	mux.HandleFunc("GET /internal/posts/{id}/cover/{cover}/access", h.postMediaAccess)
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
