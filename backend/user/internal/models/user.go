package models

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID                 uuid.UUID  `json:"id"`
	Nickname           string     `json:"nickname"`
	CreatedAt          time.Time  `json:"created_at"`
	LastOnline         *time.Time `json:"last_online"`
	PresenceVisibility string     `json:"presence_visibility"`
}
