package models

import (
	"time"

	"github.com/google/uuid"
)

type ProfileImages struct {
	Avatar *uuid.UUID `json:"avatar_media_id"`
	Banner *uuid.UUID `json:"banner_media_id"`
}

type ProfileImageChange struct {
	ID        int64      `json:"id"`
	Slot      string     `json:"slot"`
	Operation string     `json:"operation"`
	MediaID   uuid.UUID  `json:"media_id"`
	Previous  *uuid.UUID `json:"previous_media_id,omitempty"`
	Available bool       `json:"available"`
	ChangedAt time.Time  `json:"changed_at"`
}
