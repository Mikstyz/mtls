// Package uploadhttp exposes authenticated, private upload operations.
package uploadhttp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"mtls/media-processing/internal/lifecycle"
	"mtls/media-processing/internal/quarantine"
	"mtls/media-processing/internal/userclient"
)

type Service interface {
	History(context.Context, string, *lifecycle.UploadPosition) ([]lifecycle.UploadHistoryItem, error)
	Delete(context.Context, string, uuid.UUID) error
	Status(context.Context, string, uuid.UUID) (lifecycle.UploadProgress, error)
	Reserve(context.Context, string, uuid.UUID, string, int64, [32]byte) (lifecycle.Asset, error)
	Receive(context.Context, string, uuid.UUID, int64, [32]byte, io.Reader) error
	ReceiveChunk(context.Context, string, uuid.UUID, quarantine.Chunk, io.Reader) (int64, error)
}

type handler struct {
	service  Service
	origin   string
	cookie   string
	maxBytes int64
	slots    chan struct{}
}

func New(service Service, origin, cookie string, maxBytes int64, concurrent int) (http.Handler, error) {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") ||
		parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		(cookie != "mtls_session" && cookie != "__Host-mtls_session") || maxBytes < 1 || maxBytes > 1<<40 || concurrent < 1 || concurrent > 64 {
		return nil, errors.New("invalid upload settings")
	}

	h := &handler{service: service, origin: origin, cookie: cookie, maxBytes: maxBytes, slots: make(chan struct{}, concurrent)}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/media/uploads", h.reserve)
	mux.HandleFunc("PUT /api/media/uploads/{id}", h.receive)
	mux.HandleFunc("PATCH /api/media/uploads/{id}", h.receiveChunk)
	mux.HandleFunc("GET /api/media/uploads", h.history)
	mux.HandleFunc("GET /api/media/uploads/{id}", h.status)
	mux.HandleFunc("DELETE /api/media/uploads/{id}", h.delete)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(w, r)
	}), nil
}

func (h *handler) authorize(w http.ResponseWriter, r *http.Request) (string, bool) {
	origins := r.Header.Values("Origin")
	originRequired := r.Method != http.MethodGet && r.Method != http.MethodHead
	if (originRequired || len(origins) != 0) && (len(origins) != 1 || origins[0] != h.origin) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return "", false
	}

	cookies := r.CookiesNamed(h.cookie)
	if len(cookies) != 1 || cookies[0].Value == "" || len(cookies[0].Value) > 256 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return "", false
	}

	return cookies[0].Value, true
}

func (h *handler) acquire(w http.ResponseWriter) bool {
	select {
	case h.slots <- struct{}{}:
		return true
	default:
		w.Header().Set("Retry-After", "2")
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return false
	}
}

func (h *handler) reserve(w http.ResponseWriter, r *http.Request) {
	token, ok := h.authorize(w, r)
	if !ok || !h.acquire(w) {
		return
	}
	defer func() { <-h.slots }()

	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		http.Error(w, "expected JSON", http.StatusUnsupportedMediaType)
		return
	}

	var input struct {
		RequestID uuid.UUID `json:"request_id"`
		Kind      string    `json:"kind"`
		Size      int64     `json:"size"`
		Digest    string    `json:"sha256"`
	}

	r.Body = http.MaxBytesReader(w, r.Body, 2048)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil || decoder.Decode(new(any)) != io.EOF {
		http.Error(w, "invalid reservation", http.StatusBadRequest)
		return
	}

	digest, ok := decodeDigest(input.Digest)
	if !ok || input.RequestID == uuid.Nil || (input.Kind != "photo" && input.Kind != "video") || input.Size < 1 {
		http.Error(w, "invalid reservation", http.StatusBadRequest)
		return
	}

	if input.Size > h.maxBytes || (input.Kind == "photo" && input.Size > 32<<20) {
		http.Error(w, "file too large", http.StatusRequestEntityTooLarge)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	asset, err := h.service.Reserve(ctx, token, input.RequestID, input.Kind, input.Size, digest)
	if err != nil {
		writeError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		ID    uuid.UUID `json:"id"`
		State string    `json:"state"`
	}{asset.ID, asset.State})
}

func (h *handler) receive(w http.ResponseWriter, r *http.Request) {
	token, ok := h.authorize(w, r)
	if !ok {
		return
	}

	id, err := uuid.Parse(r.PathValue("id"))
	digests := r.Header.Values("X-Upload-SHA256")
	if err != nil || id == uuid.Nil || len(digests) != 1 {
		http.Error(w, "invalid upload", http.StatusBadRequest)
		return
	}

	digest, ok := decodeDigest(digests[0])
	if !ok || r.ContentLength == 0 {
		http.Error(w, "invalid upload", http.StatusBadRequest)
		return
	}

	if r.ContentLength < 0 {
		http.Error(w, "content length required", http.StatusLengthRequired)
		return
	}

	if r.ContentLength > h.maxBytes {
		http.Error(w, "file too large", http.StatusRequestEntityTooLarge)
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

	if err := h.service.Receive(ctx, token, id, r.ContentLength, digest, r.Body); err != nil {
		writeError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) status(w http.ResponseWriter, r *http.Request) {
	token, ok := h.authorize(w, r)
	if !ok {
		return
	}

	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil || id == uuid.Nil {
		http.NotFound(w, r)
		return
	}

	if !h.acquire(w) {
		return
	}
	defer func() { <-h.slots }()

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	progress, err := h.service.Status(ctx, token, id)
	if err != nil {
		writeError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		ID uuid.UUID `json:"id"`
		lifecycle.UploadProgress
	}{id, progress})
}

func (h *handler) delete(w http.ResponseWriter, r *http.Request) {
	token, ok := h.authorize(w, r)
	if !ok {
		return
	}

	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil || id == uuid.Nil {
		http.NotFound(w, r)
		return
	}

	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		http.Error(w, "unexpected body", http.StatusBadRequest)
		return
	}

	if !h.acquire(w) {
		return
	}
	defer func() { <-h.slots }()

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	if err := h.service.Delete(ctx, token, id); err != nil {
		writeError(w, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func decodeDigest(value string) ([32]byte, bool) {
	var digest [32]byte
	if len(value) != hex.EncodedLen(len(digest)) {
		return digest, false
	}

	_, err := hex.Decode(digest[:], []byte(value))
	return digest, err == nil
}

func writeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, userclient.ErrUnauthenticated):
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	case errors.Is(err, userclient.ErrForbidden):
		http.Error(w, "forbidden", http.StatusForbidden)
	case errors.Is(err, lifecycle.ErrConflict), errors.Is(err, userclient.ErrConflict):
		http.Error(w, "upload conflict", http.StatusConflict)
	case errors.Is(err, lifecycle.ErrNotFound):
		http.Error(w, "upload not found", http.StatusNotFound)
	case errors.Is(err, lifecycle.ErrQuota):
		http.Error(w, "upload quota exceeded", http.StatusTooManyRequests)
	case errors.Is(err, quarantine.ErrBusy):
		w.Header().Set("Retry-After", "1")
		http.Error(w, "upload temporarily busy", http.StatusServiceUnavailable)
	case errors.Is(err, quarantine.ErrMismatch):
		http.Error(w, "upload checksum or size mismatch", http.StatusUnprocessableEntity)
	case errors.Is(err, lifecycle.ErrInvalid), errors.Is(err, userclient.ErrInvalid):
		http.Error(w, "invalid upload", http.StatusBadRequest)
	default:
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}
}
