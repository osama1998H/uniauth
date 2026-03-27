package domain

import (
	"time"

	"github.com/google/uuid"
)

type Role struct {
	ID          uuid.UUID
	OrgID       uuid.UUID
	Name        string
	Description *string
	Permissions []Permission
	CreatedAt   time.Time
}

type Permission struct {
	ID          uuid.UUID
	Name        string // e.g. "users:read", "users:write"
	Description *string
}
