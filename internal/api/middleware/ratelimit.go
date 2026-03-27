package middleware

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"time"
)

type rateLimitCounter interface {
	IncrRateLimit(ctx context.Context, key string, window time.Duration) (int64, error)
}

// RateLimit returns a middleware that limits requests per IP per minute.
func RateLimit(redisCache rateLimitCounter, requestsPerMinute int) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := ClientIP(r)
			key := fmt.Sprintf("rl:%s", ip)

			if isNilRateLimitCounter(redisCache) {
				next.ServeHTTP(w, r)
				return
			}

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

func isNilRateLimitCounter(counter rateLimitCounter) bool {
	if counter == nil {
		return true
	}

	value := reflect.ValueOf(counter)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
