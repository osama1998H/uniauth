package token

import (
	"strings"
	"testing"
)

func TestGenerateAPIKey_Format(t *testing.T) {
	plaintext, prefix, err := GenerateAPIKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(plaintext, "uk_") {
		t.Errorf("plaintext should start with 'uk_', got %q", plaintext[:min(10, len(plaintext))])
	}
	// 32 bytes → 64 hex chars, plus "uk_" prefix = 67 chars total
	wantLen := len("uk_") + 64
	if len(plaintext) != wantLen {
		t.Errorf("plaintext length: got %d, want %d", len(plaintext), wantLen)
	}
	if !strings.HasPrefix(prefix, "uk_") {
		t.Errorf("prefix should start with 'uk_', got %q", prefix)
	}
	// prefix = first len("uk_")+8 characters of plaintext
	wantPrefix := plaintext[:len("uk_")+8]
	if prefix != wantPrefix {
		t.Errorf("prefix mismatch: got %q, want %q", prefix, wantPrefix)
	}
}

func TestGenerateAPIKey_Uniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		pt, _, err := GenerateAPIKey()
		if err != nil {
			t.Fatalf("iteration %d: unexpected error: %v", i, err)
		}
		if seen[pt] {
			t.Fatalf("duplicate key generated at iteration %d", i)
		}
		seen[pt] = true
	}
}

func TestHashAPIKey_Deterministic(t *testing.T) {
	input := "uk_abcdef1234567890"
	h1 := HashAPIKey(input)
	h2 := HashAPIKey(input)
	if h1 != h2 {
		t.Errorf("HashAPIKey should be deterministic: got %q and %q", h1, h2)
	}
}

func TestHashAPIKey_DifferentInputs(t *testing.T) {
	h1 := HashAPIKey("uk_aaaa")
	h2 := HashAPIKey("uk_bbbb")
	if h1 == h2 {
		t.Error("different inputs should produce different hashes")
	}
}

func TestHashAPIKey_NotPlaintext(t *testing.T) {
	plaintext := "uk_supersecretkey12345678"
	hash := HashAPIKey(plaintext)
	if hash == plaintext {
		t.Error("hash should not equal the plaintext key")
	}
}

func TestHashAPIKey_Length(t *testing.T) {
	// SHA-256 produces a 32-byte digest → 64 hex characters
	hash := HashAPIKey("uk_somekey")
	if len(hash) != 64 {
		t.Errorf("expected SHA-256 hex hash of length 64, got %d", len(hash))
	}
}

func TestGenerateAndHash_RoundTrip(t *testing.T) {
	// Verify that hashing the same plaintext twice gives the same result,
	// which is what the lookup path (hash → DB lookup) relies on.
	plaintext, _, err := GenerateAPIKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	h1 := HashAPIKey(plaintext)
	h2 := HashAPIKey(plaintext)
	if h1 != h2 {
		t.Error("hashing the same plaintext should always produce the same hash")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
