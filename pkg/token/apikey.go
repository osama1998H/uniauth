package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const (
	apiKeyPrefix = "uk_"
	apiKeyLength = 32 // bytes of random data
)

// GenerateAPIKey creates a new random API key.
// Returns the full plaintext key (shown to user once) and the prefix (stored in DB).
func GenerateAPIKey() (plaintext, prefix string, err error) {
	raw := make([]byte, apiKeyLength)
	if _, err = rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("generate api key: %w", err)
	}
	plaintext = apiKeyPrefix + hex.EncodeToString(raw)
	prefix = plaintext[:len(apiKeyPrefix)+8]
	return plaintext, prefix, nil
}

// HashAPIKey returns the SHA-256 hex digest of the plaintext key.
// Unlike bcrypt, SHA-256 is fast enough for per-request lookup and
// the random key provides sufficient entropy.
func HashAPIKey(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}
