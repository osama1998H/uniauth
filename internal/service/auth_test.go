package service

import (
	"errors"
	"testing"

	"github.com/osama1998h/uniauth/internal/domain"
)

// validatePassword and slugify are package-private functions tested here
// because they encapsulate security-critical logic.

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		errIs   error
	}{
		{
			name:    "valid password",
			input:   "Secure@123",
			wantErr: false,
		},
		{
			name:    "valid password with multiple specials",
			input:   "P@ssw0rd!",
			wantErr: false,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
			errIs:   domain.ErrWeakPassword,
		},
		{
			name:    "too short — 7 chars",
			input:   "Abc1!ef",
			wantErr: true,
			errIs:   domain.ErrWeakPassword,
		},
		{
			name:    "exactly 8 chars — meets all rules",
			input:   "Abcd1!ef",
			wantErr: false,
		},
		{
			name:    "no uppercase letter",
			input:   "secure@123",
			wantErr: true,
			errIs:   domain.ErrWeakPassword,
		},
		{
			name:    "no digit",
			input:   "Secure@abc",
			wantErr: true,
			errIs:   domain.ErrWeakPassword,
		},
		{
			name:    "no special character",
			input:   "Secure1234",
			wantErr: true,
			errIs:   domain.ErrWeakPassword,
		},
		{
			name:    "only uppercase and special — no digit",
			input:   "AAAAA@@@@@",
			wantErr: true,
			errIs:   domain.ErrWeakPassword,
		},
		{
			name:    "only digits",
			input:   "12345678",
			wantErr: true,
			errIs:   domain.ErrWeakPassword,
		},
		{
			name:    "spaces count as special characters",
			input:   "Secure 12",
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePassword(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tc.errIs != nil && !errors.Is(err, tc.errIs) {
					t.Errorf("error type mismatch: got %v, want errors.Is(%v)", err, tc.errIs)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestSlugify(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "simple lowercase",
			input: "acme",
			want:  "acme",
		},
		{
			name:  "uppercase converted",
			input: "ACME Corp",
			want:  "acme-corp",
		},
		{
			name:  "mixed case with spaces",
			input: "My Organization",
			want:  "my-organization",
		},
		{
			name:  "multiple spaces collapse to one dash",
			input: "foo  bar",
			want:  "foo-bar",
		},
		{
			name:  "underscores become dashes",
			input: "foo_bar",
			want:  "foo-bar",
		},
		{
			name:  "dashes preserved as single dash",
			input: "foo-bar",
			want:  "foo-bar",
		},
		{
			name:  "trailing space trimmed",
			input: "foo ",
			want:  "foo",
		},
		{
			name:  "leading space trimmed (no leading dash)",
			input: " foo",
			want:  "foo",
		},
		{
			name:  "special characters stripped",
			input: "foo!@#bar",
			want:  "foobar",
		},
		{
			name:  "numbers preserved",
			input: "org123",
			want:  "org123",
		},
		{
			name:  "all special characters",
			input: "!@#$%",
			want:  "",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "consecutive dashes collapse",
			input: "foo--bar",
			want:  "foo-bar",
		},
		{
			name:  "trailing dash trimmed",
			input: "foo-",
			want:  "foo",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := slugify(tc.input)
			if got != tc.want {
				t.Errorf("slugify(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestHashString(t *testing.T) {
	t.Run("deterministic", func(t *testing.T) {
		h1 := hashString("hello world")
		h2 := hashString("hello world")
		if h1 != h2 {
			t.Error("hashString should be deterministic")
		}
	})

	t.Run("different inputs produce different hashes", func(t *testing.T) {
		h1 := hashString("token-a")
		h2 := hashString("token-b")
		if h1 == h2 {
			t.Error("different inputs should not produce the same hash")
		}
	})

	t.Run("output is 64 hex chars (SHA-256)", func(t *testing.T) {
		h := hashString("some-refresh-token")
		if len(h) != 64 {
			t.Errorf("expected 64-char hex output, got %d", len(h))
		}
	})

	t.Run("hash does not equal input", func(t *testing.T) {
		input := "plaintext"
		if hashString(input) == input {
			t.Error("hash should not equal the plaintext")
		}
	})
}
