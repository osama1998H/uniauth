package domain

import (
	"time"

	"github.com/google/uuid"
)

type APIKey struct {
	ID         uuid.UUID
	OrgID      uuid.UUID
	Name       string
	KeyPrefix  string // first 8 chars, safe to display
	KeyHash    string
	Scopes     []string
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
	CreatedAt  time.Time
}

func (k *APIKey) IsValid() bool {
	if k.RevokedAt != nil {
		return false
	}
	if k.ExpiresAt != nil && k.ExpiresAt.Before(time.Now()) {
		return false
	}
	return true
}
