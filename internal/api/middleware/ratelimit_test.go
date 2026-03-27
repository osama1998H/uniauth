package middleware

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientIPResolverResolve(t *testing.T) {
	t.Parallel()

	resolverNoTrust := NewClientIPResolver(nil)
	resolverTrustedProxy := NewClientIPResolver(mustParseCIDRs(t, "10.0.0.0/8", "192.168.0.0/16"))

	tests := []struct {
		name       string
		resolver   *ClientIPResolver
		remoteAddr string
		headers    map[string]string
		want       string
	}{
		{
			name:       "untrusted direct client cannot spoof X-Forwarded-For",
			resolver:   resolverNoTrust,
			remoteAddr: "203.0.113.10:4000",
			headers: map[string]string{
				"X-Forwarded-For": "198.51.100.10",
			},
			want: "203.0.113.10",
		},
		{
			name:       "untrusted direct client cannot spoof X-Real-IP",
			resolver:   resolverNoTrust,
			remoteAddr: "203.0.113.11:4000",
			headers: map[string]string{
				"X-Real-IP": "198.51.100.11",
			},
			want: "203.0.113.11",
		},
		{
			name:       "trusted proxy uses X-Forwarded-For client",
			resolver:   resolverTrustedProxy,
			remoteAddr: "10.1.2.3:4000",
			headers: map[string]string{
				"X-Forwarded-For": "198.51.100.20",
			},
			want: "198.51.100.20",
		},
		{
			name:       "trusted proxy walks X-Forwarded-For right to left",
			resolver:   resolverTrustedProxy,
			remoteAddr: "10.1.2.3:4000",
			headers: map[string]string{
				"X-Forwarded-For": "198.51.100.30, 192.168.1.10, 10.9.9.9",
			},
			want: "198.51.100.30",
		},
		{
			name:       "invalid forwarded header falls back to peer IP",
			resolver:   resolverTrustedProxy,
			remoteAddr: "10.1.2.3:4000",
			headers: map[string]string{
				"X-Forwarded-For": "not-an-ip",
			},
			want: "10.1.2.3",
		},
		{
			name:       "remote addr with port is normalized",
			resolver:   resolverNoTrust,
			remoteAddr: "203.0.113.50:54321",
			want:       "203.0.113.50",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remoteAddr
			for key, value := range tc.headers {
				r.Header.Set(key, value)
			}

			got := tc.resolver.Resolve(r)
			if got != tc.want {
				t.Fatalf("Resolve() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRateLimitUsesResolvedClientIP(t *testing.T) {
	t.Parallel()

	t.Run("untrusted peer ignores spoofed forwarded headers", func(t *testing.T) {
		t.Parallel()

		counter := newFakeRateLimitCounter()
		handler := PopulateClientIP(NewClientIPResolver(nil))(RateLimit(counter, 10)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})))

		requests := []*http.Request{
			newRateLimitedRequest("203.0.113.99:4000", map[string]string{"X-Forwarded-For": "198.51.100.1"}),
			newRateLimitedRequest("203.0.113.99:4000", map[string]string{"X-Forwarded-For": "198.51.100.2"}),
		}

		for _, req := range requests {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d", rec.Code)
			}
		}

		want := []string{"rl:203.0.113.99", "rl:203.0.113.99"}
		assertKeys(t, counter.keys, want)
	})

	t.Run("trusted proxy buckets by resolved client IP", func(t *testing.T) {
		t.Parallel()

		counter := newFakeRateLimitCounter()
		handler := PopulateClientIP(NewClientIPResolver(mustParseCIDRs(t, "10.0.0.0/8")))(RateLimit(counter, 10)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})))

		requests := []*http.Request{
			newRateLimitedRequest("10.0.0.5:4000", map[string]string{"X-Forwarded-For": "198.51.100.10"}),
			newRateLimitedRequest("10.0.0.5:4000", map[string]string{"X-Forwarded-For": "198.51.100.11"}),
		}

		for _, req := range requests {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d", rec.Code)
			}
		}

		want := []string{"rl:198.51.100.10", "rl:198.51.100.11"}
		assertKeys(t, counter.keys, want)
	})
}

type fakeRateLimitCounter struct {
	counts map[string]int64
	keys   []string
}

func newFakeRateLimitCounter() *fakeRateLimitCounter {
	return &fakeRateLimitCounter{counts: make(map[string]int64)}
}

func (f *fakeRateLimitCounter) IncrRateLimit(_ context.Context, key string, _ time.Duration) (int64, error) {
	f.counts[key]++
	f.keys = append(f.keys, key)
	return f.counts[key], nil
}

func newRateLimitedRequest(remoteAddr string, headers map[string]string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remoteAddr
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	return req
}

func mustParseCIDRs(t *testing.T, values ...string) []*net.IPNet {
	t.Helper()

	ranges := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			t.Fatalf("parse cidr %q: %v", value, err)
		}
		ranges = append(ranges, network)
	}
	return ranges
}

func assertKeys(t *testing.T, got, want []string) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("key count = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("key[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
