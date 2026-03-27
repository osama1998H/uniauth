package domain

import (
	"time"

	"github.com/google/uuid"
)

type Session struct {
	ID               uuid.UUID
	UserID           uuid.UUID
	RefreshTokenHash string
	UserAgent        *string
	IPAddress        *string
	ExpiresAt        time.Time
	RevokedAt        *time.Time
	CreatedAt        time.Time
}

func (s *Session) IsValid() bool {
	return s.RevokedAt == nil && s.ExpiresAt.After(time.Now())
}
