package testutil

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/osama1998h/uniauth/internal/repository/cache"
)

// RequireTestCache returns a Redis-backed cache using REDIS_URL.
func RequireTestCache(t testing.TB) *cache.Cache {
	t.Helper()

	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		t.Skip("REDIS_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	redisCache, err := cache.New(ctx, redisURL)
	if err != nil {
		t.Fatalf("connect test redis: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := redisCache.Close(); closeErr != nil {
			t.Fatalf("close test redis: %v", closeErr)
		}
	})

	return redisCache
}

// RequireEnv ensures the named environment variables are present.
func RequireEnv(t testing.TB, names ...string) {
	t.Helper()

	for _, name := range names {
		if os.Getenv(name) == "" {
			t.Skip(fmt.Sprintf("%s is not set", name))
		}
	}
}
