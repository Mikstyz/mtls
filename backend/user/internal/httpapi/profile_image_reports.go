package httpapi

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"

	"github.com/google/uuid"
	"mtls/user/internal/models"
)

func (h *Handler) profileImageReport(w http.ResponseWriter, r *http.Request) {
	reportID, err := uuid.Parse(r.PathValue("report"))
	if err != nil || reportID == uuid.Nil {
		http.NotFound(w, r)
		return
	}

	if r.Method != http.MethodPut {
		viewer, ok := h.authenticate(w, r)
		if !ok {
			return
		}

		report, err := h.users.OwnProfileImageReport(r.Context(), viewer.UserID, reportID)
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}

		writeJSON(w, report)
		return
	}

	viewer, ok := h.authenticateParticipant(w, r)
	if !ok {
		return
	}

	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		http.Error(w, "expected JSON", http.StatusUnsupportedMediaType)
		return
	}

	var input struct {
		OwnerID uuid.UUID `json:"owner_id"`
		Slot    string    `json:"slot"`
		MediaID uuid.UUID `json:"media_id"`
		Reason  string    `json:"reason"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF ||
		input.OwnerID == uuid.Nil || input.OwnerID == viewer.UserID || input.MediaID == uuid.Nil ||
		(input.Slot != "avatar" && input.Slot != "banner") || !validProfileImageReportReason(input.Reason) {
		http.Error(w, "invalid profile image report", http.StatusBadRequest)
		return
	}

	active, err := h.activeAccounts(r.Context(), []uuid.UUID{input.OwnerID})
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if !active[input.OwnerID] {
		http.NotFound(w, r)
		return
	}

	status, err := h.users.ReportProfileImage(r.Context(), viewer.UserID, reportID, models.ProfileImageReport{
		OwnerID: input.OwnerID,
		Slot:    input.Slot,
		MediaID: input.MediaID,
		Reason:  input.Reason,
	})
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	switch status {
	case http.StatusCreated, http.StatusOK:
		w.WriteHeader(status)
	case http.StatusNotFound:
		http.NotFound(w, r)
	case http.StatusBadRequest:
		http.Error(w, "invalid profile image report", status)
	case http.StatusConflict:
		http.Error(w, "profile image report conflict", status)
	case http.StatusTooManyRequests:
		w.Header().Set("Retry-After", "3600")
		http.Error(w, "too many profile image reports", status)
	default:
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}
}

func validProfileImageReportReason(reason string) bool {
	switch reason {
	case "spam", "harassment", "consent", "age_safety", "other":
		return true
	default:
		return false
	}
}

func (h *Handler) profileImageModeration(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.authenticateSession(w, r, "/internal/session/moderator")
	if !ok {
		return
	}

	if r.Method != http.MethodPut {
		cases, err := h.users.ProfileImageModerationQueue(r.Context(), actor.UserID)
		if err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}

		writeJSON(w, struct {
			Cases []models.ProfileImageCase `json:"cases"`
		}{Cases: cases})
		return
	}

	id, err := uuid.Parse(r.PathValue("case"))
	if err != nil || id == uuid.Nil {
		http.NotFound(w, r)
		return
	}

	var input struct {
		Request uuid.UUID `json:"request_id"`
		Action  string    `json:"action"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF ||
		input.Request == uuid.Nil || (input.Action != "hide" && input.Action != "remove" && input.Action != "dismiss") {
		http.Error(w, "invalid profile moderation decision", http.StatusBadRequest)
		return
	}

	status, err := h.users.DecideProfileImageReport(r.Context(), actor.UserID, id, input.Request, input.Action)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	switch status {
	case http.StatusNoContent:
		w.WriteHeader(status)
	case http.StatusNotFound:
		http.NotFound(w, r)
	case http.StatusConflict:
		http.Error(w, "profile moderation decision conflict", status)
	default:
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}
}

func (h *Handler) profileModerationMediaAccess(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.authenticateSession(w, r, "/internal/session/moderator")
	if !ok {
		return
	}

	id, caseErr := uuid.Parse(r.PathValue("case"))
	media, mediaErr := uuid.Parse(r.PathValue("id"))
	if caseErr != nil || mediaErr != nil || id == uuid.Nil || media == uuid.Nil {
		http.NotFound(w, r)
		return
	}

	owner, err := h.users.ProfileModerationMediaOwner(r.Context(), actor.UserID, id, media)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if owner == uuid.Nil {
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

	w.WriteHeader(http.StatusNoContent)
}
