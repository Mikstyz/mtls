package uploadhttp

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"mtls/media-processing/internal/quarantine"
)

func (h *handler) receiveChunk(w http.ResponseWriter, r *http.Request) {
	token, ok := h.authorize(w, r)
	if !ok {
		return
	}

	id, err := uuid.Parse(r.PathValue("id"))
	offset, offsetOK := uploadNumber(r.Header, "Upload-Offset")
	total, totalOK := uploadNumber(r.Header, "Upload-Length")
	digests := r.Header.Values("X-Upload-SHA256")
	if err != nil || id == uuid.Nil || !offsetOK || !totalOK || total < 1 || offset > total || len(digests) != 1 {
		http.Error(w, "invalid upload", http.StatusBadRequest)
		return
	}

	digest, ok := decodeDigest(digests[0])
	length := r.ContentLength
	if !ok {
		http.Error(w, "invalid upload", http.StatusBadRequest)
		return
	}
	if length < 0 {
		http.Error(w, "content length required", http.StatusLengthRequired)
		return
	}
	if total > h.maxBytes || length > quarantine.MaxChunkBytes {
		http.Error(w, "file or chunk too large", http.StatusRequestEntityTooLarge)
		return
	}
	if length > total-offset || (length == 0 && offset != total) {
		http.Error(w, "invalid upload length", http.StatusBadRequest)
		return
	}
	if r.Header.Get("Content-Type") != "application/octet-stream" {
		http.Error(w, "expected binary data", http.StatusUnsupportedMediaType)
		return
	}

	if !h.acquire(w) {
		return
	}
	defer func() { <-h.slots }()

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Minute)
	defer cancel()

	chunk := quarantine.Chunk{Total: total, Offset: offset, Length: length, Digest: digest}
	next, err := h.service.ReceiveChunk(ctx, token, id, chunk, r.Body)
	if errors.Is(err, quarantine.ErrOffset) {
		w.Header().Set("Upload-Offset", strconv.FormatInt(next, 10))
		http.Error(w, "upload offset conflict", http.StatusConflict)
		return
	}
	if err != nil {
		writeError(w, err)
		return
	}

	w.Header().Set("Upload-Offset", strconv.FormatInt(next, 10))
	w.WriteHeader(http.StatusNoContent)
}

func uploadNumber(headers http.Header, name string) (int64, bool) {
	values := headers.Values(name)
	if len(values) != 1 || len(values[0]) == 0 || len(values[0]) > 19 {
		return 0, false
	}
	for _, b := range []byte(values[0]) {
		if b < '0' || b > '9' {
			return 0, false
		}
	}

	value, err := strconv.ParseInt(values[0], 10, 64)
	return value, err == nil
}
