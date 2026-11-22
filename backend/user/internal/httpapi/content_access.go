package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
)

func (h *Handler) checkPostMedia(ctx context.Context, post, media, owner, viewer uuid.UUID, cover bool) (bool, bool, string, error) {
	segment := "/media/"
	if cover {
		segment = "/cover/"
	}
	return h.checkContentMedia(ctx, "/internal/posts/"+post.String()+segment+media.String()+"/access", owner, viewer)
}

func (h *Handler) checkContentMedia(ctx context.Context, path string, owner, viewer uuid.UUID) (bool, bool, string, error) {
	if h.contentSearchURL == "" {
		return false, false, "", errors.New("content service is not configured")
	}

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, h.contentSearchURL+path, nil)

	if err != nil {
		return false, false, "", err
	}

	request.Header.Set("X-Internal-Secret", h.contentSearchSecret)
	request.Header.Set("X-Media-Owner", owner.String())
	request.Header.Set("X-Viewer-ID", viewer.String())

	response, err := h.client.Do(request)

	if err != nil {
		return false, false, "", err
	}
	defer response.Body.Close()

	switch response.StatusCode {
	case http.StatusNoContent:
		values := response.Header.Values("X-Playback-Popular")
		frames := response.Header.Values("X-Cover-Frame")
		var frame string
		if len(frames) > 0 {
			if len(frames) != 1 || (frames[0] != "poster-25.jpg" && frames[0] != "poster-60.jpg") {
				return false, false, "", errors.New("invalid content cover frame")
			}
			frame = frames[0]
		}
		return true, len(values) == 1 && values[0] == "1", frame, nil
	case http.StatusNotFound:
		return false, false, "", nil
	default:
		return false, false, "", errors.New("content access check unavailable")
	}
}

func (h *Handler) moderationMediaAccess(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	actor, ok := h.authenticateSession(w, r.WithContext(ctx), "/internal/session/moderator")
	if !ok {
		return
	}

	asset, assetErr := uuid.Parse(r.PathValue("id"))
	target, targetErr := uuid.Parse(r.PathValue("case"))
	if assetErr != nil || targetErr != nil || asset == uuid.Nil || target == uuid.Nil {
		http.NotFound(w, r)
		return
	}

	owner, _, _, allowed, err := h.users.MediaAccessOwner(ctx, asset, actor.UserID, true)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if !allowed {
		http.NotFound(w, r)
		return
	}

	active, err := h.activeAccounts(ctx, []uuid.UUID{owner})
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if !active[owner] {
		http.NotFound(w, r)
		return
	}

	path := "/internal/moderation/cases/" + target.String() + "/media/" + asset.String() + "/access"
	allowed, _, _, err = h.checkContentMedia(ctx, path, owner, actor.UserID)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if !allowed {
		http.NotFound(w, r)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
