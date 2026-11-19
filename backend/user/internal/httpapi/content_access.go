package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
)

func (h *Handler) checkPostMedia(ctx context.Context, post, media, owner, viewer uuid.UUID) (bool, error) {
	if h.contentSearchURL == "" {
		return false, errors.New("content service is not configured")
	}

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	path := "/internal/posts/" + post.String() + "/media/" + media.String() + "/access"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, h.contentSearchURL+path, nil)

	if err != nil {
		return false, err
	}

	request.Header.Set("X-Internal-Secret", h.contentSearchSecret)
	request.Header.Set("X-Media-Owner", owner.String())
	request.Header.Set("X-Viewer-ID", viewer.String())

	response, err := h.client.Do(request)

	if err != nil {
		return false, err
	}
	defer response.Body.Close()

	switch response.StatusCode {
	case http.StatusNoContent:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, errors.New("content access check unavailable")
	}
}
