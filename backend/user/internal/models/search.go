package models

import "github.com/google/uuid"

type SearchUser struct {
	ID       uuid.UUID `json:"id"`
	Nickname string    `json:"nickname"`
}
