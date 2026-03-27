package token

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func newTestMaker() *Maker {
	return NewMaker("supersecretkey-at-least-32-chars!!", 15*time.Minute, 7*24*time.Hour)
}

func TestMaker_CreateAccessToken(t *testing.T) {
	maker := newTestMaker()
	userID := uuid.New()
	orgID := uuid.New()

	tokenStr, claims, err := maker.CreateAccessToken(userID, orgID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tokenStr == "" {
		t.Fatal("expected non-empty token string")
	}
	if claims.UserID != userID {
		t.Errorf("UserID mismatch: got %v, want %v", claims.UserID, userID)
	}
	if claims.OrgID != orgID {
		t.Errorf("OrgID mismatch: got %v, want %v", claims.OrgID, orgID)
	}
	if claims.TokenID == uuid.Nil {
		t.Error("expected non-nil TokenID (jti)")
	}
	if claims.ExpiresAt == nil {
		t.Fatal("expected ExpiresAt to be set")
	}
	wantExpiry := time.Now().Add(15 * time.Minute)
	diff := claims.ExpiresAt.Time.Sub(wantExpiry)
	if diff < -2*time.Second || diff > 2*time.Second {
		t.Errorf("access token expiry out of range: got %v", claims.ExpiresAt.Time)
	}
}

func TestMaker_CreateRefreshToken(t *testing.T) {
	maker := newTestMaker()
	userID := uuid.New()
	orgID := uuid.New()

	tokenStr, claims, err := maker.CreateRefreshToken(userID, orgID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tokenStr == "" {
		t.Fatal("expected non-empty token string")
	}
	wantExpiry := time.Now().Add(7 * 24 * time.Hour)
	diff := claims.ExpiresAt.Time.Sub(wantExpiry)
	if diff < -2*time.Second || diff > 2*time.Second {
		t.Errorf("refresh token expiry out of range: got %v", claims.ExpiresAt.Time)
	}
}

func TestMaker_AccessAndRefreshTokensAreDifferent(t *testing.T) {
	maker := newTestMaker()
	userID := uuid.New()
	orgID := uuid.New()

	access, _, _ := maker.CreateAccessToken(userID, orgID)
	refresh, _, _ := maker.CreateRefreshToken(userID, orgID)

	if access == refresh {
		t.Error("access and refresh tokens should be different strings")
	}
}

func TestMaker_Verify_Valid(t *testing.T) {
	maker := newTestMaker()
	userID := uuid.New()
	orgID := uuid.New()

	tokenStr, _, err := maker.CreateAccessToken(userID, orgID)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	claims, err := maker.Verify(tokenStr)
	if err != nil {
		t.Fatalf("unexpected error verifying valid token: %v", err)
	}
	if claims.UserID != userID {
		t.Errorf("UserID mismatch: got %v, want %v", claims.UserID, userID)
	}
	if claims.OrgID != orgID {
		t.Errorf("OrgID mismatch: got %v, want %v", claims.OrgID, orgID)
	}
}

func TestMaker_Verify_ExpiredToken(t *testing.T) {
	// Maker with a -1s access duration to create immediately-expired tokens
	maker := NewMaker("supersecretkey-at-least-32-chars!!", -time.Second, 7*24*time.Hour)
	userID := uuid.New()
	orgID := uuid.New()

	tokenStr, _, err := maker.CreateAccessToken(userID, orgID)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	_, err = maker.Verify(tokenStr)
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
}

func TestMaker_Verify_WrongSecret(t *testing.T) {
	maker1 := NewMaker("supersecretkey-at-least-32-chars!!", 15*time.Minute, 7*24*time.Hour)
	maker2 := NewMaker("a-totally-different-secret-key!!!!", 15*time.Minute, 7*24*time.Hour)

	userID := uuid.New()
	orgID := uuid.New()

	tokenStr, _, err := maker1.CreateAccessToken(userID, orgID)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	_, err = maker2.Verify(tokenStr)
	if err == nil {
		t.Fatal("expected error when verifying with wrong secret, got nil")
	}
}

func TestMaker_Verify_TamperedToken(t *testing.T) {
	maker := newTestMaker()
	userID := uuid.New()
	orgID := uuid.New()

	tokenStr, _, _ := maker.CreateAccessToken(userID, orgID)
	// Flip the last character to tamper with the signature
	tampered := tokenStr[:len(tokenStr)-1] + "X"
	if tampered[len(tampered)-1] == tokenStr[len(tokenStr)-1] {
		tampered = tokenStr[:len(tokenStr)-1] + "Y"
	}

	_, err := maker.Verify(tampered)
	if err == nil {
		t.Fatal("expected error for tampered token, got nil")
	}
}

func TestMaker_Verify_EmptyString(t *testing.T) {
	maker := newTestMaker()
	_, err := maker.Verify("")
	if err == nil {
		t.Fatal("expected error for empty token string, got nil")
	}
}

func TestMaker_Verify_MalformedToken(t *testing.T) {
	maker := newTestMaker()
	_, err := maker.Verify("not.a.valid.jwt")
	if err == nil {
		t.Fatal("expected error for malformed token, got nil")
	}
}

func TestMaker_Verify_AlgorithmSubstitution(t *testing.T) {
	// Build a token whose header claims alg=none — should be rejected
	maker := newTestMaker()
	// Manually craft a "none" algorithm token (header.payload.empty-sig)
	noneToken := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1aWQiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDAiLCJvaWQiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDAiLCJqdGkiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDAiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6OTk5OTk5OTk5OX0."
	_, err := maker.Verify(noneToken)
	if err == nil {
		t.Fatal("expected error for 'none' algorithm token, got nil")
	}
	if !strings.Contains(err.Error(), "unexpected signing method") && !strings.Contains(err.Error(), "parse token") {
		t.Logf("error (acceptable): %v", err)
	}
}

func TestMaker_EachTokenHasUniqueJTI(t *testing.T) {
	maker := newTestMaker()
	userID := uuid.New()
	orgID := uuid.New()

	_, c1, _ := maker.CreateAccessToken(userID, orgID)
	_, c2, _ := maker.CreateAccessToken(userID, orgID)

	if c1.TokenID == c2.TokenID {
		t.Error("two tokens for the same user should have different JTIs")
	}
}
