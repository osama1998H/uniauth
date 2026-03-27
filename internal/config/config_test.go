package config

import (
	"strings"
	"testing"
)

const validJWTSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestParseTrustedProxyCIDRs(t *testing.T) {
	t.Parallel()

	t.Run("normalizes single IP entries", func(t *testing.T) {
		t.Parallel()

		ranges, err := parseTrustedProxyCIDRs("203.0.113.10,2001:db8::1")
		if err != nil {
			t.Fatalf("parseTrustedProxyCIDRs() error = %v", err)
		}
		if len(ranges) != 2 {
			t.Fatalf("len(ranges) = %d, want 2", len(ranges))
		}
		if got := ranges[0].String(); got != "203.0.113.10/32" {
			t.Fatalf("ranges[0] = %q, want %q", got, "203.0.113.10/32")
		}
		if got := ranges[1].String(); got != "2001:db8::1/128" {
			t.Fatalf("ranges[1] = %q, want %q", got, "2001:db8::1/128")
		}
	})

	t.Run("accepts explicit CIDRs", func(t *testing.T) {
		t.Parallel()

		ranges, err := parseTrustedProxyCIDRs("10.0.0.0/8, 192.168.0.0/16")
		if err != nil {
			t.Fatalf("parseTrustedProxyCIDRs() error = %v", err)
		}
		if len(ranges) != 2 {
			t.Fatalf("len(ranges) = %d, want 2", len(ranges))
		}
	})

	t.Run("rejects invalid entries", func(t *testing.T) {
		t.Parallel()

		if _, err := parseTrustedProxyCIDRs("10.0.0.0/8,not-a-cidr"); err == nil {
			t.Fatal("expected error for invalid trusted proxy entry")
		}
	})
}

func TestValidateJWTSecret(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		secret  string
		wantErr bool
	}{
		{
			name:    "accepts random 32 plus character secret",
			secret:  validJWTSecret,
			wantErr: false,
		},
		{
			name:    "rejects blank secret",
			secret:  "   ",
			wantErr: true,
		},
		{
			name:    "rejects short secret",
			secret:  "short-secret",
			wantErr: true,
		},
		{
			name:    "rejects placeholder variant after normalization",
			secret:  "Change-Me in production, use a long random string!!!",
			wantErr: true,
		},
		{
			name:    "rejects placeholder variant with punctuation and case changes",
			secret:  "Your-Secret minimum_32 characters long!!!",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := validateJWTSecret(tc.secret)
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}

func TestLoadValidatesJWTSecret(t *testing.T) {
	tests := []struct {
		name         string
		secret       string
		wantErr      bool
		checkMessage bool
	}{
		{
			name:    "rejects short secret",
			secret:  "too-short-secret",
			wantErr: true,
		},
		{
			name:         "rejects placeholder secret without echoing it",
			secret:       "change-me-in-production-use-a-long-random-string",
			wantErr:      true,
			checkMessage: true,
		},
		{
			name:    "accepts valid secret",
			secret:  validJWTSecret,
			wantErr: false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("JWT_SECRET", tc.secret)
			t.Setenv("TRUSTED_PROXY_CIDRS", "")

			cfg, err := Load()
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), "openssl rand -hex 32") {
					t.Fatalf("error %q does not include generation guidance", err.Error())
				}
				if tc.checkMessage && strings.Contains(err.Error(), tc.secret) {
					t.Fatalf("error %q leaked configured secret", err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if cfg.Auth.JWTSecret != tc.secret {
				t.Fatalf("cfg.Auth.JWTSecret = %q, want %q", cfg.Auth.JWTSecret, tc.secret)
			}
		})
	}
}
