package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/osama1998h/uniauth/internal/testutil"
	"github.com/osama1998h/uniauth/pkg/token"
)

func BenchmarkJWTAuth_BlacklistLookup(b *testing.B) {
	testutil.RequireEnv(b, "REDIS_URL")
	maker := token.NewMaker(testJWTSecret, 15*time.Minute, 7*24*time.Hour)
	redisCache := testutil.RequireTestCache(b)
	userID := uuid.New()
	orgID := uuid.New()

	tokenStr, _, err := maker.CreateAccessToken(userID, orgID)
	if err != nil {
		b.Fatalf("create access token: %v", err)
	}

	handler := JWTAuth(maker, redisCache, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
		req.Header.Set("Authorization", "Bearer "+tokenStr)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("JWTAuth status = %d, want %d", rec.Code, http.StatusOK)
		}
	}
}

func BenchmarkRateLimit_APIRequest(b *testing.B) {
	testutil.RequireEnv(b, "REDIS_URL")
	redisCache := testutil.RequireTestCache(b)
	handler := RateLimit(redisCache, 1_000_000_000, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
		req.RemoteAddr = "203.0.113.13:4000"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("RateLimit status = %d, want %d", rec.Code, http.StatusOK)
		}
	}
}
