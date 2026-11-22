package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"mtls/user/internal/models"
)

func (h *Handler) profileImageOwnerModeration(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.authenticate(w, r)
	if !ok {
		return
	}

	if r.Method != http.MethodPut {
		items, err := h.users.ProfileImageNotices(r.Context(), actor.UserID)
		if err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}

		writeJSON(w, struct {
			Notices []models.ProfileImageNotice `json:"notices"`
		}{Notices: items})
		return
	}

	var input struct {
		Statement string `json:"statement"`
	}
	id, ok := readProfileAppeal(w, r, &input)
	if !ok {
		return
	}
	if strings.TrimSpace(input.Statement) == "" || strings.ContainsRune(input.Statement, 0) || utf8.RuneCountInString(input.Statement) > 1000 {
		http.Error(w, "invalid appeal statement", http.StatusBadRequest)
		return
	}

	status, err := h.users.SubmitProfileImageAppeal(r.Context(), actor.UserID, id, input.Statement)
	writeProfileAppealStatus(w, r, status, err)
}

func (h *Handler) profileImageAppealModeration(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.authenticateSession(w, r, "/internal/session/moderator")
	if !ok {
		return
	}

	if r.Method != http.MethodPut {
		items, err := h.users.ProfileImageAppeals(r.Context(), actor.UserID)
		if err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}

		writeJSON(w, struct {
			Appeals []models.ProfileImageAppeal `json:"appeals"`
		}{Appeals: items})
		return
	}

	var input struct {
		Outcome string `json:"outcome"`
	}
	id, ok := readProfileAppeal(w, r, &input)
	if !ok {
		return
	}
	if input.Outcome != "upheld" && input.Outcome != "reversed" {
		http.Error(w, "invalid appeal outcome", http.StatusBadRequest)
		return
	}

	status, err := h.users.ReviewProfileImageAppeal(r.Context(), actor.UserID, id, input.Outcome)
	writeProfileAppealStatus(w, r, status, err)
}

func readProfileAppeal(w http.ResponseWriter, r *http.Request, input any) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("case"))
	if err != nil || id == uuid.Nil {
		http.NotFound(w, r)
		return uuid.Nil, false
	}

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	decoder.DisallowUnknownFields()
	if decoder.Decode(input) != nil || decoder.Decode(new(any)) != io.EOF {
		http.Error(w, "invalid appeal", http.StatusBadRequest)
		return uuid.Nil, false
	}

	return id, true
}

func writeProfileAppealStatus(w http.ResponseWriter, r *http.Request, status int, err error) {
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	switch status {
	case http.StatusCreated, http.StatusNoContent:
		w.WriteHeader(status)
	case http.StatusNotFound:
		http.NotFound(w, r)
	case http.StatusBadRequest:
		http.Error(w, "invalid appeal", status)
	case http.StatusConflict:
		http.Error(w, "profile image appeal conflict", status)
	default:
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}
}
