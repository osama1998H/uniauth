package middleware

import (
	"fmt"
	"net/http"
	"time"

	"github.com/osama1998h/uniauth/internal/repository/cache"
)

// RateLimit returns a middleware that limits requests per IP per minute.
func RateLimit(redisCache *cache.Cache, requestsPerMinute int) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := realIP(r)
			key := fmt.Sprintf("rl:%s", ip)

			count, err := redisCache.IncrRateLimit(r.Context(), key, time.Minute)
			if err != nil {
				// Redis unavailable — allow the request but log
				next.ServeHTTP(w, r)
				return
			}

			if count > int64(requestsPerMinute) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "60")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":"rate limit exceeded"}`))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func realIP(r *http.Request) string {
	return RealIPFromRequest(r)
}

// RealIPFromRequest extracts the real client IP from common proxy headers.
func RealIPFromRequest(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	return r.RemoteAddr
}
