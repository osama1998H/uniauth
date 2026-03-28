package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/osama1998h/uniauth/internal/api"
	"github.com/osama1998h/uniauth/internal/config"
	"github.com/osama1998h/uniauth/internal/testutil"
)

func TestRouterDoesNotRateLimitHealthOrReady(t *testing.T) {
	testutil.RequireEnv(t, "DATABASE_URL", "REDIS_URL")

	store := testutil.RequireTestStore(t)
	redisCache := testutil.RequireTestCache(t)
	handler := api.NewRouter(newLowRateLimitConfig(), store, redisCache, testutil.DiscardLogger())

	tests := []struct {
		name string
		path string
		ip   string
	}{
		{name: "health", path: "/health", ip: "203.0.113.31:4000"},
		{name: "ready", path: "/ready", ip: "203.0.113.32:4000"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for i := 0; i < 2; i++ {
				req := httptest.NewRequest(http.MethodGet, tc.path, nil)
				req.RemoteAddr = tc.ip
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code != http.StatusOK {
					t.Fatalf("%s request %d status = %d, want %d, body=%s", tc.path, i+1, rec.Code, http.StatusOK, rec.Body.String())
				}
			}
		})
	}
}

func TestRouterStillRateLimitsAPIRoutes(t *testing.T) {
	testutil.RequireEnv(t, "DATABASE_URL", "REDIS_URL")

	store := testutil.RequireTestStore(t)
	redisCache := testutil.RequireTestCache(t)
	handler := api.NewRouter(newLowRateLimitConfig(), store, redisCache, testutil.DiscardLogger())

	req1 := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	req1.RemoteAddr = "203.0.113.33:4000"
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusUnauthorized {
		t.Fatalf("first API request status = %d, want %d", rec1.Code, http.StatusUnauthorized)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	req2.RemoteAddr = "203.0.113.33:4000"
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("second API request status = %d, want %d, body=%s", rec2.Code, http.StatusTooManyRequests, rec2.Body.String())
	}
}

func newLowRateLimitConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			Environment: "development",
		},
		Auth: config.AuthConfig{
			JWTSecret:            routerTestJWTSecret,
			AccessTokenDuration:  15 * time.Minute,
			RefreshTokenDuration: 7 * 24 * time.Hour,
			RateLimitPerMinute:   1,
		},
		Email: config.EmailConfig{
			BaseURL: "http://localhost:8080",
		},
	}
}
