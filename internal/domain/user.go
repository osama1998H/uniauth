package domain

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID              uuid.UUID
	OrgID           uuid.UUID
	Email           string
	HashedPassword  string
	FullName        *string
	IsActive        bool
	IsSuperuser     bool
	EmailVerifiedAt *time.Time
	LastLoginAt     *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}
