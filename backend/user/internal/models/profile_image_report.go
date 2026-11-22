package models

import (
	"time"

	"github.com/google/uuid"
)

type ProfileImageReport struct {
	OwnerID   uuid.UUID `json:"owner_id"`
	Slot      string    `json:"slot"`
	MediaID   uuid.UUID `json:"media_id"`
	Reason    string    `json:"reason"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

type ProfileImageCase struct {
	CaseID    uuid.UUID `json:"case_id"`
	OwnerID   uuid.UUID `json:"owner_id"`
	Slot      string    `json:"slot"`
	MediaID   uuid.UUID `json:"media_id"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
}

type ProfileImageNotice struct {
	CaseID    uuid.UUID `json:"case_id"`
	Slot      string    `json:"slot"`
	MediaID   uuid.UUID `json:"media_id"`
	Reason    string    `json:"reason"`
	DecidedAt time.Time `json:"decided_at"`
	Appeal    *string   `json:"appeal,omitempty"`
}

type ProfileImageAppeal struct {
	CaseID      uuid.UUID `json:"case_id"`
	OwnerID     uuid.UUID `json:"owner_id"`
	Slot        string    `json:"slot"`
	MediaID     uuid.UUID `json:"media_id"`
	Reason      string    `json:"reason"`
	Statement   string    `json:"statement"`
	SubmittedAt time.Time `json:"submitted_at"`
}
