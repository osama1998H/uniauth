package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/osama1998h/uniauth/internal/api"
	"github.com/osama1998h/uniauth/internal/config"
	"github.com/osama1998h/uniauth/internal/domain"
	"github.com/osama1998h/uniauth/internal/testutil"
	"github.com/osama1998h/uniauth/pkg/token"
)

const benchmarkJWTSecret = "benchmark-secret-at-least-32-chars!"

func BenchmarkRouter_Health(b *testing.B) {
	handler := newBenchmarkRouter(b)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		req.RemoteAddr = "203.0.113.10:4000"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("GET /health status = %d, want %d", rec.Code, http.StatusOK)
		}
	}
}

func BenchmarkRouter_ListUsers_Permitted(b *testing.B) {
	handler, accessToken := newBenchmarkListUsersRouter(b, false)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
		req.RemoteAddr = "203.0.113.11:4000"
		req.Header.Set("Authorization", "Bearer "+accessToken)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("GET /api/v1/users status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
		}
	}
}

func BenchmarkRouter_ListUsers_Superuser(b *testing.B) {
	handler, accessToken := newBenchmarkListUsersRouter(b, true)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
		req.RemoteAddr = "203.0.113.12:4000"
		req.Header.Set("Authorization", "Bearer "+accessToken)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("GET /api/v1/users status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
		}
	}
}

func newBenchmarkRouter(b *testing.B) http.Handler {
	b.Helper()

	testutil.RequireEnv(b, "DATABASE_URL", "REDIS_URL", "JWT_SECRET")
	store := testutil.RequireTestStore(b)
	redisCache := testutil.RequireTestCache(b)

	return api.NewRouter(newBenchmarkConfig(), store, redisCache, testutil.DiscardLogger())
}

func newBenchmarkListUsersRouter(b *testing.B, superuser bool) (http.Handler, string) {
	b.Helper()

	testutil.RequireEnv(b, "DATABASE_URL", "REDIS_URL", "JWT_SECRET")
	store := testutil.RequireTestStore(b)
	redisCache := testutil.RequireTestCache(b)
	handler := api.NewRouter(newBenchmarkConfig(), store, redisCache, testutil.DiscardLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	org := testutil.CreateOrganization(b, store, "bench-users-org")
	for i := 0; i < 20; i++ {
		testutil.CreateUser(b, store, org.ID, "bench-users-seed")
	}

	var userID uuid.UUID
	if superuser {
		admin, err := store.CreateUser(ctx, org.ID, "bench-superuser@example.com", "hashed-password", nil, true)
		if err != nil {
			b.Fatalf("CreateUser(superuser) error = %v", err)
		}
		userID = admin.ID
	} else {
		user := testutil.CreateUser(b, store, org.ID, "bench-users-reader")
		grantPermissionToUser(b, ctx, store, org.ID, user.ID, domain.PermissionUsersRead)
		userID = user.ID
	}

	return handler, issueBenchmarkAccessToken(b, userID, org.ID)
}

func newBenchmarkConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			Environment: "development",
		},
		Auth: config.AuthConfig{
			JWTSecret:            benchmarkJWTSecret,
			AccessTokenDuration:  15 * time.Minute,
			RefreshTokenDuration: 7 * 24 * time.Hour,
			RateLimitPerMinute:   1_000_000_000,
		},
		Email: config.EmailConfig{
			BaseURL: "http://localhost:8080",
		},
	}
}

func issueBenchmarkAccessToken(b *testing.B, userID, orgID uuid.UUID) string {
	b.Helper()

	maker := token.NewMaker(benchmarkJWTSecret, 15*time.Minute, 7*24*time.Hour)
	tokenStr, _, err := maker.CreateAccessToken(userID, orgID)
	if err != nil {
		b.Fatalf("CreateAccessToken() error = %v", err)
	}
	return tokenStr
}
