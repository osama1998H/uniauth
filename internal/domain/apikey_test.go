package domain

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAPIKey_IsValid(t *testing.T) {
	now := time.Now()
	future := now.Add(time.Hour)
	past := now.Add(-time.Hour)
	revokedAt := now.Add(-time.Minute)

	tests := []struct {
		name string
		k    APIKey
		want bool
	}{
		{
			name: "valid key with no expiry",
			k:    APIKey{ID: uuid.New(), RevokedAt: nil, ExpiresAt: nil},
			want: true,
		},
		{
			name: "valid key with future expiry",
			k:    APIKey{ID: uuid.New(), RevokedAt: nil, ExpiresAt: &future},
			want: true,
		},
		{
			name: "revoked key",
			k:    APIKey{ID: uuid.New(), RevokedAt: &revokedAt, ExpiresAt: nil},
			want: false,
		},
		{
			name: "revoked key with future expiry",
			k:    APIKey{ID: uuid.New(), RevokedAt: &revokedAt, ExpiresAt: &future},
			want: false,
		},
		{
			name: "expired key",
			k:    APIKey{ID: uuid.New(), RevokedAt: nil, ExpiresAt: &past},
			want: false,
		},
		{
			name: "revoked and expired key",
			k:    APIKey{ID: uuid.New(), RevokedAt: &revokedAt, ExpiresAt: &past},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.k.IsValid()
			if got != tc.want {
				t.Errorf("IsValid() = %v, want %v", got, tc.want)
			}
		})
	}
}
