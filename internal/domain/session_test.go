package domain

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSession_IsValid(t *testing.T) {
	now := time.Now()
	future := now.Add(time.Hour)
	past := now.Add(-time.Hour)
	revokedAt := now.Add(-time.Minute)

	tests := []struct {
		name string
		s    Session
		want bool
	}{
		{
			name: "valid session",
			s:    Session{ID: uuid.New(), ExpiresAt: future, RevokedAt: nil},
			want: true,
		},
		{
			name: "revoked session",
			s:    Session{ID: uuid.New(), ExpiresAt: future, RevokedAt: &revokedAt},
			want: false,
		},
		{
			name: "expired session",
			s:    Session{ID: uuid.New(), ExpiresAt: past, RevokedAt: nil},
			want: false,
		},
		{
			name: "revoked and expired session",
			s:    Session{ID: uuid.New(), ExpiresAt: past, RevokedAt: &revokedAt},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.s.IsValid()
			if got != tc.want {
				t.Errorf("IsValid() = %v, want %v", got, tc.want)
			}
		})
	}
}
