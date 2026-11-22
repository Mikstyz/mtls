package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"mtls/content/internal/catalog"
	"mtls/shared/pagination"
)

func (h *Handler) comments(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if h.user == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	post, err := uuid.Parse(r.PathValue("id"))
	if err != nil || post == uuid.Nil {
		http.NotFound(w, r)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	sessionPath := "/api/users/me/participation"
	if r.Method == http.MethodDelete {
		sessionPath = "/api/users/me"
	}

	viewer, err := h.user.sessionUser(ctx, r, sessionPath)
	if err != nil {
		writeContentError(w, r, err)
		return
	}
	if r.Method != http.MethodDelete {
		author, err := h.catalog.ViewablePostAuthor(ctx, viewer, post)
		if err != nil {
			writeContentError(w, r, err)
			return
		}
		if err := h.user.checkAuthorAccess(ctx, r, author); err != nil {
			writeContentError(w, r, err)
			return
		}
	}

	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		h.listComments(ctx, w, r, post, viewer)
		return
	}
	id, err := uuid.Parse(r.PathValue("comment"))
	if err != nil || id == uuid.Nil {
		http.NotFound(w, r)
		return
	}
	var body *string
	if r.Method == http.MethodPut {
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			http.Error(w, "expected JSON", http.StatusUnsupportedMediaType)
			return
		}
		var input struct {
			Body string `json:"body"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || strings.TrimSpace(input.Body) == "" || strings.ContainsRune(input.Body, 0) || utf8.RuneCountInString(input.Body) > 2000 {
			http.Error(w, "invalid comment", http.StatusBadRequest)
			return
		}
		body = &input.Body
	} else if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	status, err := h.catalog.WriteComment(ctx, post, viewer, id, body)
	if err != nil {
		writeContentError(w, r, err)
		return
	}
	if status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "60")
	}
	w.WriteHeader(status)
}

func (h *Handler) listComments(ctx context.Context, w http.ResponseWriter, r *http.Request, post, viewer uuid.UUID) {
	limit, token, ok := pageFilter(r.URL.RawQuery)
	if !ok {
		http.Error(w, "invalid filter", http.StatusBadRequest)
		return
	}
	cursor, err := pagination.NewCursor(h.secret, "mtls/content/comments/v1", viewer.String()+"/"+post.String())
	if err != nil {
		writeContentError(w, r, err)
		return
	}
	var before *time.Time
	var beforeID uuid.UUID
	if token != "" {
		id, instant, err := cursor.Decode(token)
		if err != nil {
			http.Error(w, "invalid cursor", http.StatusBadRequest)
			return
		}
		beforeID, before = id, &instant
	}

	items, err := h.catalog.ListComments(ctx, post, viewer, limit+1, before, beforeID)
	if err != nil {
		writeContentError(w, r, err)
		return
	}
	var next string
	if len(items) > limit {
		items = items[:limit]
		last := items[limit-1]
		next, err = cursor.Encode(last.ID, last.CreatedAt)
		if err != nil {
			writeContentError(w, r, err)
			return
		}
	}

	authors := make([]uuid.UUID, 0, len(items))
	for _, item := range items {
		authors = append(authors, item.AuthorID)
	}
	active, err := h.user.activeAuthors(ctx, r, authors)
	if err != nil {
		writeContentError(w, r, err)
		return
	}

	visible := items[:0]
	for _, item := range items {
		if active[item.AuthorID] {
			visible = append(visible, item)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Comments []catalog.Comment `json:"comments"`
		Next     string            `json:"next_cursor,omitempty"`
	}{visible, next})
}
