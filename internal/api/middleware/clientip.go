package middleware

import (
	"context"
	"net"
	"net/http"
	"strings"
)

// ClientIPResolver resolves the effective client IP, honoring forwarded
// headers only when the immediate peer is a configured trusted proxy.
type ClientIPResolver struct {
	trustedProxies []*net.IPNet
}

// NewClientIPResolver creates a new client IP resolver.
func NewClientIPResolver(trustedProxies []*net.IPNet) *ClientIPResolver {
	return &ClientIPResolver{trustedProxies: trustedProxies}
}

// PopulateClientIP stores the resolved client IP in the request context so
// downstream middleware and handlers use the same value.
func PopulateClientIP(resolver *ClientIPResolver) func(next http.Handler) http.Handler {
	if resolver == nil {
		resolver = NewClientIPResolver(nil)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := resolver.Resolve(r)
			ctx := context.WithValue(r.Context(), ContextKeyClientIP, clientIP)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Resolve returns the effective client IP for the request.
func (r *ClientIPResolver) Resolve(req *http.Request) string {
	peerIP, ok := parseIP(req.RemoteAddr)
	if !ok {
		return ""
	}

	if !r.isTrusted(peerIP) {
		return peerIP.String()
	}

	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		clientIP, ok, invalid := r.clientIPFromXFF(xff)
		if invalid {
			return peerIP.String()
		}
		if ok {
			return clientIP.String()
		}
	}

	if clientIP, ok, invalid := headerIP(req.Header.Get("X-Real-IP")); invalid {
		return peerIP.String()
	} else if ok {
		return clientIP.String()
	}

	if clientIP, ok, invalid := headerIP(req.Header.Get("True-Client-IP")); invalid {
		return peerIP.String()
	} else if ok {
		return clientIP.String()
	}

	return peerIP.String()
}

func (r *ClientIPResolver) clientIPFromXFF(header string) (net.IP, bool, bool) {
	parts := strings.Split(header, ",")
	ips := make([]net.IP, 0, len(parts))
	for _, part := range parts {
		ip, ok := parseIP(strings.TrimSpace(part))
		if !ok {
			return nil, false, true
		}
		ips = append(ips, ip)
	}

	for i := len(ips) - 1; i >= 0; i-- {
		if r.isTrusted(ips[i]) {
			continue
		}
		return ips[i], true, false
	}

	return nil, false, false
}

func (r *ClientIPResolver) isTrusted(ip net.IP) bool {
	for _, network := range r.trustedProxies {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// ClientIP returns the resolved client IP from context or falls back to the
// socket peer IP when the middleware has not populated the context.
func ClientIP(r *http.Request) string {
	if ip, ok := GetClientIP(r.Context()); ok && ip != "" {
		return ip
	}

	ip, ok := parseIP(r.RemoteAddr)
	if !ok {
		return ""
	}
	return ip.String()
}

// GetClientIP retrieves the resolved client IP from the context.
func GetClientIP(ctx context.Context) (string, bool) {
	ip, ok := ctx.Value(ContextKeyClientIP).(string)
	return ip, ok
}

func headerIP(value string) (net.IP, bool, bool) {
	if strings.TrimSpace(value) == "" {
		return nil, false, false
	}

	ip, ok := parseIP(value)
	if !ok {
		return nil, false, true
	}
	return ip, true, false
}

func parseIP(value string) (net.IP, bool) {
	candidate := strings.TrimSpace(value)
	if candidate == "" {
		return nil, false
	}

	if host, _, err := net.SplitHostPort(candidate); err == nil {
		candidate = host
	} else if strings.HasPrefix(candidate, "[") && strings.HasSuffix(candidate, "]") {
		candidate = strings.TrimPrefix(strings.TrimSuffix(candidate, "]"), "[")
	}

	ip := net.ParseIP(candidate)
	if ip == nil {
		return nil, false
	}
	return ip, true
}
