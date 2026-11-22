package httpapi

import (
	"encoding/json"
	"io"
	"mime"
	"net/http"

	"mtls/user/internal/models"
)

func (h *Handler) playbackSettings(w http.ResponseWriter, r *http.Request) {
	viewer, ok := h.authenticate(w, r)
	if !ok {
		return
	}

	if r.Method == http.MethodPut {
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			http.Error(w, "expected JSON", http.StatusUnsupportedMediaType)
			return
		}

		var settings models.PlaybackSettings
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&settings) != nil || decoder.Decode(new(any)) != io.EOF || !settings.Valid() {
			http.Error(w, "invalid playback settings", http.StatusBadRequest)
			return
		}
		if err := h.users.SetPlaybackSettings(r.Context(), viewer.UserID, settings); !h.handleUserError(w, err) {
			return
		}

		w.WriteHeader(http.StatusNoContent)
		return
	}

	settings, err := h.users.PlaybackSettings(r.Context(), viewer.UserID)
	if !h.handleUserError(w, err) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(settings)
}
