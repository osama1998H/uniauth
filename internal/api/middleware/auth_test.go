package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/osama1998h/uniauth/pkg/token"
)

func newTestMaker() *token.Maker {
	return token.NewMaker("supersecretkey-at-least-32-chars!!", 15*time.Minute, 7*24*time.Hour)
}

// sentinel handler to detect that the next handler was reached
func nextHandler(reached *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*reached = true
		w.WriteHeader(http.StatusOK)
	})
}

func TestJWTAuth_ValidToken(t *testing.T) {
	maker := newTestMaker()
	userID := uuid.New()
	orgID := uuid.New()

	tokenStr, _, err := maker.CreateAccessToken(userID, orgID)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	reached := false
	handler := JWTAuth(maker, nil)(nextHandler(&reached))

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+tokenStr)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !reached {
		t.Error("next handler was not called for valid token")
	}
}

func TestJWTAuth_ValidToken_InjectsContext(t *testing.T) {
	maker := newTestMaker()
	userID := uuid.New()
	orgID := uuid.New()

	tokenStr, _, _ := maker.CreateAccessToken(userID, orgID)

	var gotUserID, gotOrgID uuid.UUID
	captureHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserID, _ = GetUserID(r.Context())
		gotOrgID, _ = GetOrgID(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := JWTAuth(maker, nil)(captureHandler)
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+tokenStr)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if gotUserID != userID {
		t.Errorf("context UserID: got %v, want %v", gotUserID, userID)
	}
	if gotOrgID != orgID {
		t.Errorf("context OrgID: got %v, want %v", gotOrgID, orgID)
	}
}

func TestJWTAuth_MissingAuthorizationHeader(t *testing.T) {
	maker := newTestMaker()
	reached := false
	handler := JWTAuth(maker, nil)(nextHandler(&reached))

	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
	if reached {
		t.Error("next handler should not be called without Authorization header")
	}
}

func TestJWTAuth_MalformedBearer(t *testing.T) {
	maker := newTestMaker()
	reached := false
	handler := JWTAuth(maker, nil)(nextHandler(&reached))

	r := httptest.NewRequest("GET", "/", nil)
	// Missing "Bearer " prefix
	r.Header.Set("Authorization", "Token somevalue")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
	if reached {
		t.Error("next handler should not be called for malformed bearer")
	}
}

func TestJWTAuth_ExpiredToken(t *testing.T) {
	expiredMaker := token.NewMaker("supersecretkey-at-least-32-chars!!", -time.Second, 7*24*time.Hour)
	validMaker := newTestMaker()

	userID := uuid.New()
	orgID := uuid.New()
	tokenStr, _, _ := expiredMaker.CreateAccessToken(userID, orgID)

	reached := false
	// Use the valid maker for the middleware (correct secret, but token is expired)
	handler := JWTAuth(validMaker, nil)(nextHandler(&reached))

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+tokenStr)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for expired token, got %d", w.Code)
	}
	if reached {
		t.Error("next handler should not be called for expired token")
	}
}

func TestJWTAuth_WrongSecret(t *testing.T) {
	signingMaker := token.NewMaker("supersecretkey-at-least-32-chars!!", 15*time.Minute, 7*24*time.Hour)
	verifyingMaker := token.NewMaker("a-totally-different-secret-key!!!!", 15*time.Minute, 7*24*time.Hour)

	userID := uuid.New()
	orgID := uuid.New()
	tokenStr, _, _ := signingMaker.CreateAccessToken(userID, orgID)

	reached := false
	handler := JWTAuth(verifyingMaker, nil)(nextHandler(&reached))

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+tokenStr)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong-secret token, got %d", w.Code)
	}
	if reached {
		t.Error("next handler should not be called for token signed with wrong secret")
	}
}

func TestJWTAuth_InvalidTokenString(t *testing.T) {
	maker := newTestMaker()
	reached := false
	handler := JWTAuth(maker, nil)(nextHandler(&reached))

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer not-a-real-jwt")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid token, got %d", w.Code)
	}
	if reached {
		t.Error("next handler should not be called for invalid token")
	}
}

func TestGetUserID(t *testing.T) {
	t.Run("present in context", func(t *testing.T) {
		id := uuid.New()
		ctx := context.WithValue(context.Background(), ContextKeyUserID, id)
		got, ok := GetUserID(ctx)
		if !ok {
			t.Fatal("expected ok=true")
		}
		if got != id {
			t.Errorf("got %v, want %v", got, id)
		}
	})

	t.Run("absent from context", func(t *testing.T) {
		_, ok := GetUserID(context.Background())
		if ok {
			t.Error("expected ok=false for empty context")
		}
	})

	t.Run("wrong type in context", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ContextKeyUserID, "not-a-uuid")
		_, ok := GetUserID(ctx)
		if ok {
			t.Error("expected ok=false for wrong type")
		}
	})
}

func TestGetOrgID(t *testing.T) {
	t.Run("present in context", func(t *testing.T) {
		id := uuid.New()
		ctx := context.WithValue(context.Background(), ContextKeyOrgID, id)
		got, ok := GetOrgID(ctx)
		if !ok {
			t.Fatal("expected ok=true")
		}
		if got != id {
			t.Errorf("got %v, want %v", got, id)
		}
	})

	t.Run("absent from context", func(t *testing.T) {
		_, ok := GetOrgID(context.Background())
		if ok {
			t.Error("expected ok=false for empty context")
		}
	})
}
