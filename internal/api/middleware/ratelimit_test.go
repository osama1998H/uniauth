package middleware

import (
	"net/http/httptest"
	"testing"
)

func TestRealIPFromRequest(t *testing.T) {
	tests := []struct {
		name           string
		xRealIP        string
		xForwardedFor  string
		remoteAddr     string
		want           string
	}{
		{
			name:       "X-Real-IP takes priority",
			xRealIP:    "1.2.3.4",
			xForwardedFor: "5.6.7.8",
			remoteAddr: "9.10.11.12:5000",
			want:       "1.2.3.4",
		},
		{
			name:          "X-Forwarded-For used when X-Real-IP absent",
			xRealIP:       "",
			xForwardedFor: "5.6.7.8, 9.10.11.12",
			remoteAddr:    "9.10.11.12:5000",
			want:          "5.6.7.8, 9.10.11.12",
		},
		{
			name:          "RemoteAddr used when both proxy headers absent",
			xRealIP:       "",
			xForwardedFor: "",
			remoteAddr:    "203.0.113.5:54321",
			want:          "203.0.113.5:54321",
		},
		{
			name:       "X-Real-IP takes priority over RemoteAddr",
			xRealIP:    "10.0.0.1",
			xForwardedFor: "",
			remoteAddr: "192.168.1.1:1234",
			want:       "10.0.0.1",
		},
		{
			name:          "empty X-Forwarded-For falls back to RemoteAddr",
			xRealIP:       "",
			xForwardedFor: "",
			remoteAddr:    "127.0.0.1:8080",
			want:          "127.0.0.1:8080",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tc.remoteAddr
			if tc.xRealIP != "" {
				r.Header.Set("X-Real-IP", tc.xRealIP)
			}
			if tc.xForwardedFor != "" {
				r.Header.Set("X-Forwarded-For", tc.xForwardedFor)
			}

			got := RealIPFromRequest(r)
			if got != tc.want {
				t.Errorf("RealIPFromRequest() = %q, want %q", got, tc.want)
			}
		})
	}
}
