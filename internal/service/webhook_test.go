package service

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/osama1998h/uniauth/internal/domain"
	"github.com/osama1998h/uniauth/internal/testutil"
)

type staticWebhookResolver struct {
	lookups map[string][]net.IPAddr
	errs    map[string]error
}

func (r staticWebhookResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if err, ok := r.errs[host]; ok {
		return nil, err
	}
	addrs, ok := r.lookups[host]
	if !ok {
		return nil, errors.New("host not found")
	}
	out := make([]net.IPAddr, len(addrs))
	copy(out, addrs)
	return out, nil
}

func TestWebhookServiceValidateWebhookURL(t *testing.T) {
	resolver := staticWebhookResolver{
		lookups: map[string][]net.IPAddr{
			"public.example":  {{IP: net.ParseIP("93.184.216.34")}},
			"blocked.example": {{IP: net.ParseIP("10.0.0.5")}},
		},
	}
	svc := newWebhookServiceWithNetworking(nil, testutil.DiscardLogger(), resolver, nil)

	tests := []struct {
		name    string
		rawURL  string
		wantErr error
	}{
		{
			name:   "accepts public https hostname",
			rawURL: "https://public.example/hooks",
		},
		{
			name:    "rejects non https",
			rawURL:  "http://public.example/hooks",
			wantErr: domain.ErrInvalidInput,
		},
		{
			name:    "rejects relative url",
			rawURL:  "/hooks",
			wantErr: domain.ErrInvalidInput,
		},
		{
			name:    "rejects missing host",
			rawURL:  "https:///hooks",
			wantErr: domain.ErrInvalidInput,
		},
		{
			name:    "rejects credentials in url",
			rawURL:  "https://user:pass@public.example/hooks",
			wantErr: domain.ErrInvalidInput,
		},
		{
			name:    "rejects localhost",
			rawURL:  "https://localhost/hooks",
			wantErr: domain.ErrInvalidInput,
		},
		{
			name:    "rejects loopback ipv4",
			rawURL:  "https://127.0.0.1/hooks",
			wantErr: domain.ErrInvalidInput,
		},
		{
			name:    "rejects metadata ip",
			rawURL:  "https://169.254.169.254/latest/meta-data",
			wantErr: domain.ErrInvalidInput,
		},
		{
			name:    "rejects private ipv4",
			rawURL:  "https://10.0.0.5/hooks",
			wantErr: domain.ErrInvalidInput,
		},
		{
			name:    "rejects ipv6 ula",
			rawURL:  "https://[fc00::1]/hooks",
			wantErr: domain.ErrInvalidInput,
		},
		{
			name:    "rejects hostname resolving only to blocked ips",
			rawURL:  "https://blocked.example/hooks",
			wantErr: domain.ErrInvalidInput,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := svc.validateWebhookURL(context.Background(), tc.rawURL)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("expected error %v, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("validate webhook url: %v", err)
			}
			if got != tc.rawURL {
				t.Fatalf("validated url = %q, want %q", got, tc.rawURL)
			}
		})
	}
}

func TestWebhookServiceSafeDialContextUsesOnlyAllowedIPs(t *testing.T) {
	resolver := staticWebhookResolver{
		lookups: map[string][]net.IPAddr{
			"mixed.example": {
				{IP: net.ParseIP("127.0.0.1")},
				{IP: net.ParseIP("93.184.216.34")},
			},
		},
	}

	var dialed []string
	dialer := func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed = append(dialed, address)
		client, server := net.Pipe()
		t.Cleanup(func() { _ = server.Close() })
		return client, nil
	}

	svc := newWebhookServiceWithNetworking(nil, testutil.DiscardLogger(), resolver, dialer)
	conn, err := svc.safeDialContext(context.Background(), "tcp", "mixed.example:443")
	if err != nil {
		t.Fatalf("safe dial context: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	if len(dialed) != 1 {
		t.Fatalf("dialed %d addresses, want 1", len(dialed))
	}
	if dialed[0] != "93.184.216.34:443" {
		t.Fatalf("dialed address = %q, want public IP only", dialed[0])
	}
}

func TestWebhookServiceDeliverRejectsUnsafeResolvedTarget(t *testing.T) {
	resolver := staticWebhookResolver{
		lookups: map[string][]net.IPAddr{
			"legacy.example": {{IP: net.ParseIP("127.0.0.1")}},
		},
	}

	dialCount := 0
	dialer := func(ctx context.Context, network, address string) (net.Conn, error) {
		dialCount++
		return nil, errors.New("dial should not be reached for blocked targets")
	}

	svc := newWebhookServiceWithNetworking(nil, testutil.DiscardLogger(), resolver, dialer)
	err := svc.deliver(context.Background(), "https://legacy.example/hooks", "whsec_test", "user.login", map[string]any{"user_id": "123"})
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
	if dialCount != 0 {
		t.Fatalf("dial count = %d, want 0", dialCount)
	}
}

func TestWebhookServiceClientDisablesRedirects(t *testing.T) {
	svc := NewWebhookService(nil, testutil.DiscardLogger())
	req, err := http.NewRequest(http.MethodGet, "https://public.example/redirect", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	if got := svc.client.CheckRedirect(req, nil); !errors.Is(got, http.ErrUseLastResponse) {
		t.Fatalf("CheckRedirect error = %v, want %v", got, http.ErrUseLastResponse)
	}
}

func TestWebhookServiceCreateRejectsUnsafeURL(t *testing.T) {
	store := testutil.RequireTestStore(t)
	svc := NewWebhookService(store, testutil.DiscardLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	org := testutil.CreateOrganization(t, store, "webhook-unsafe-org")
	_, err := svc.Create(ctx, org.ID, "https://127.0.0.1/hooks", []string{"user.login"})
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestWebhookServiceCreateAndUpdatePersistValidatedURL(t *testing.T) {
	store := testutil.RequireTestStore(t)
	resolver := staticWebhookResolver{
		lookups: map[string][]net.IPAddr{
			"public.example":     {{IP: net.ParseIP("93.184.216.34")}},
			"public-two.example": {{IP: net.ParseIP("93.184.216.35")}},
		},
	}
	svc := newWebhookServiceWithNetworking(store, testutil.DiscardLogger(), resolver, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	org := testutil.CreateOrganization(t, store, "webhook-valid-org")
	createURL := "https://public.example/hooks"

	out, err := svc.Create(ctx, org.ID, createURL, []string{"user.login"})
	if err != nil {
		t.Fatalf("create webhook: %v", err)
	}
	if out.Webhook.URL != createURL {
		t.Fatalf("created url = %q, want %q", out.Webhook.URL, createURL)
	}
	if !strings.HasPrefix(out.Secret, "whsec_") {
		t.Fatalf("secret = %q, want whsec_ prefix", out.Secret)
	}

	updateURL := "https://public-two.example/hooks/v2"
	isActive := false
	updated, err := svc.Update(ctx, out.Webhook.ID, org.ID, &updateURL, nil, &isActive)
	if err != nil {
		t.Fatalf("update webhook: %v", err)
	}
	if updated.URL != updateURL {
		t.Fatalf("updated url = %q, want %q", updated.URL, updateURL)
	}
	if updated.IsActive {
		t.Fatal("expected webhook to be inactive after update")
	}
}
