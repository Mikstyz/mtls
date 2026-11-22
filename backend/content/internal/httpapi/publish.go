package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"mime"
	"net/http"
	"time"

	"github.com/google/uuid"
	"mtls/content/internal/catalog"
)

func (h *Handler) publishDraft(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if h.user == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	input := struct {
		Revision   int64  `json:"revision"`
		Visibility string `json:"visibility"`
	}{Visibility: "private"}
	id, ok := readPostCommand(w, r, &input)

	if !ok {
		return
	}
	if !validPostRevision(input.Revision) || (input.Visibility != "private" && input.Visibility != "public") {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	author, err := h.user.author(ctx, r)
	if err != nil {
		writeContentError(w, r, err)
		return
	}

	draft, err := h.catalog.DraftForPublication(ctx, author, id, input.Revision)
	if err != nil {
		writeContentError(w, r, err)
		return
	}

	var duration *int64
	for i, value := range draft.MediaIDs {
		media, err := uuid.Parse(value)
		if err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}

		kind, length, err := h.user.ownedMedia(ctx, r, media)
		if err != nil {
			writeContentError(w, r, err)
			return
		}
		if kind != draft.Kind {
			writeContentError(w, r, catalog.ErrInvalidDraft)
			return
		}
		if i == 0 {
			duration = length
		}
	}

	next, err := h.catalog.PublishPost(ctx, author, id, input.Revision, input.Visibility, duration)
	if err != nil {
		writeContentError(w, r, err)
		return
	}

	writePostRevision(w, next)
}

func readPostRevision(w http.ResponseWriter, r *http.Request) (uuid.UUID, int64, bool) {
	var input struct {
		Revision int64 `json:"revision"`
	}
	id, ok := readPostCommand(w, r, &input)

	if !ok {
		return uuid.Nil, 0, false
	}
	if !validPostRevision(input.Revision) {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return uuid.Nil, 0, false
	}

	return id, input.Revision, true
}

func readPostCommand(w http.ResponseWriter, r *http.Request, input any) (uuid.UUID, bool) {
	return readPostCommandLimit(w, r, input, 512)
}

func readPostCommandLimit(w http.ResponseWriter, r *http.Request, input any, limit int64) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	mediaType, _, mediaErr := mime.ParseMediaType(r.Header.Get("Content-Type"))

	if err != nil || id == uuid.Nil || mediaErr != nil || mediaType != "application/json" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return uuid.Nil, false
	}

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	decoder.DisallowUnknownFields()

	if decoder.Decode(input) != nil || decoder.Decode(new(any)) != io.EOF {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return uuid.Nil, false
	}

	return id, true
}

func validPostRevision(revision int64) bool {
	return revision > 0 && revision < math.MaxInt64
}

func writePostRevision(w http.ResponseWriter, revision int64) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Revision int64 `json:"revision"`
	}{Revision: revision})
}
