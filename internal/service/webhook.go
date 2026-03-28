package service

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/osama1998h/uniauth/internal/domain"
	db "github.com/osama1998h/uniauth/internal/repository/postgres"
)

var carrierGradeNATPrefix = netip.MustParsePrefix("100.64.0.0/10")

const webhookRequestTimeout = 10 * time.Second

type webhookResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

type webhookDialContext func(ctx context.Context, network, address string) (net.Conn, error)

type webhookDispatchJob struct {
	orgID   uuid.UUID
	event   string
	payload any
}

// WebhookService dispatches webhook events to registered endpoints.
type WebhookService struct {
	store       *db.Store
	logger      *slog.Logger
	resolver    webhookResolver
	dialContext webhookDialContext
	client      *http.Client
	queue       *asyncDispatcher[webhookDispatchJob]
}

// NewWebhookService creates a WebhookService.
func NewWebhookService(store *db.Store, logger *slog.Logger) *WebhookService {
	dialer := &net.Dialer{Timeout: webhookRequestTimeout, KeepAlive: 30 * time.Second}
	return newWebhookServiceWithNetworking(store, logger, net.DefaultResolver, dialer.DialContext)
}

func newWebhookServiceWithNetworking(
	store *db.Store,
	logger *slog.Logger,
	resolver webhookResolver,
	dialContext webhookDialContext,
) *WebhookService {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	if dialContext == nil {
		dialer := &net.Dialer{Timeout: webhookRequestTimeout, KeepAlive: 30 * time.Second}
		dialContext = dialer.DialContext
	}

	svc := &WebhookService{
		store:       store,
		logger:      logger,
		resolver:    resolver,
		dialContext: dialContext,
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = svc.safeDialContext

	svc.client = &http.Client{
		Timeout:   webhookRequestTimeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	svc.queue = newAsyncDispatcher("webhook_dispatch", logger, 256, 4, func(job webhookDispatchJob) {
		if svc.store == nil {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		hooks, err := svc.store.ListActiveWebhooksForEvent(ctx, job.orgID, job.event)
		if err != nil {
			if svc.logger != nil {
				svc.logger.Error("webhook: list hooks", "error", err)
			}
			return
		}
		for _, hook := range hooks {
			if err := svc.deliver(ctx, hook.URL, hook.Secret, job.event, job.payload); err != nil && svc.logger != nil {
				svc.logger.Warn("webhook: delivery skipped", "url", hook.URL, "error", err)
			}
		}
	})

	return svc
}

// CreateWebhookOutput includes the stored webhook row plus the plaintext
// signing secret, which is shown only once at creation time.
type CreateWebhookOutput struct {
	Webhook *db.Webhook
	Secret  string
}

// List returns all webhook endpoints for an organization.
func (w *WebhookService) List(ctx context.Context, orgID uuid.UUID) ([]*db.Webhook, error) {
	return w.store.ListWebhooksByOrg(ctx, orgID)
}

// Create validates and stores a new webhook endpoint.
func (w *WebhookService) Create(ctx context.Context, orgID uuid.UUID, rawURL string, events []string) (*CreateWebhookOutput, error) {
	if len(events) == 0 {
		return nil, fmt.Errorf("%w: events are required", domain.ErrInvalidInput)
	}

	validatedURL, err := w.validateWebhookURL(ctx, rawURL)
	if err != nil {
		return nil, err
	}

	secret, err := generateWebhookSecret()
	if err != nil {
		return nil, fmt.Errorf("generate webhook secret: %w", err)
	}

	hook, err := w.store.CreateWebhook(ctx, orgID, validatedURL, events, secret)
	if err != nil {
		return nil, fmt.Errorf("create webhook: %w", err)
	}

	return &CreateWebhookOutput{Webhook: hook, Secret: secret}, nil
}

// Update validates the webhook target before persisting changes.
func (w *WebhookService) Update(ctx context.Context, id, orgID uuid.UUID, rawURL *string, events []string, isActive *bool) (*db.Webhook, error) {
	var validatedURL *string
	if rawURL != nil {
		urlStr, err := w.validateWebhookURL(ctx, *rawURL)
		if err != nil {
			return nil, err
		}
		validatedURL = &urlStr
	}

	hook, err := w.store.UpdateWebhook(ctx, id, orgID, validatedURL, events, isActive)
	if err != nil {
		return nil, fmt.Errorf("update webhook: %w", err)
	}
	return hook, nil
}

// Delete removes a webhook endpoint.
func (w *WebhookService) Delete(ctx context.Context, id, orgID uuid.UUID) error {
	if err := w.store.DeleteWebhook(ctx, id, orgID); err != nil {
		return fmt.Errorf("delete webhook: %w", err)
	}
	return nil
}

// Dispatch fires webhook events for a given org+event asynchronously.
func (w *WebhookService) Dispatch(orgID uuid.UUID, event string, payload any) {
	w.queue.Enqueue(webhookDispatchJob{orgID: orgID, event: event, payload: payload})
}

func (w *WebhookService) deliver(ctx context.Context, targetURL, secret, event string, payload any) error {
	body, err := json.Marshal(map[string]any{
		"event":        event,
		"data":         payload,
		"delivered_at": time.Now().UTC(),
	})
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	sig := computeHMAC(secret, body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-UniAuth-Signature", "sha256="+sig)
	req.Header.Set("X-UniAuth-Event", event)

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("deliver request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		w.logger.Warn("webhook: non-2xx response", "url", targetURL, "status", resp.StatusCode)
	}
	return nil
}

func (w *WebhookService) validateWebhookURL(ctx context.Context, rawURL string) (string, error) {
	if strings.TrimSpace(rawURL) == "" {
		return "", fmt.Errorf("%w: webhook URL is required", domain.ErrInvalidInput)
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("%w: webhook URL is malformed", domain.ErrInvalidInput)
	}
	if !parsedURL.IsAbs() || !strings.EqualFold(parsedURL.Scheme, "https") {
		return "", fmt.Errorf("%w: webhook URL must use https", domain.ErrInvalidInput)
	}
	if parsedURL.Host == "" || parsedURL.Hostname() == "" {
		return "", fmt.Errorf("%w: webhook URL must include a host", domain.ErrInvalidInput)
	}
	if parsedURL.User != nil {
		return "", fmt.Errorf("%w: webhook URL must not include credentials", domain.ErrInvalidInput)
	}

	if _, err := w.lookupAllowedIPs(ctx, parsedURL.Hostname()); err != nil {
		return "", err
	}

	return parsedURL.String(), nil
}

func (w *WebhookService) safeDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("parse webhook address: %w", err)
	}

	allowedIPs, err := w.lookupAllowedIPs(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve webhook destination: %w", err)
	}

	var lastErr error
	for _, ip := range allowedIPs {
		conn, err := w.dialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, fmt.Errorf("dial webhook destination: %w", lastErr)
	}

	return nil, fmt.Errorf("dial webhook destination: no reachable public IPs")
}

func (w *WebhookService) lookupAllowedIPs(ctx context.Context, host string) ([]net.IP, error) {
	trimmedHost := strings.TrimSuffix(host, ".")
	if strings.EqualFold(trimmedHost, "localhost") {
		return nil, fmt.Errorf("%w: webhook host must resolve to a public IP", domain.ErrInvalidInput)
	}

	if parsedIP := net.ParseIP(trimmedHost); parsedIP != nil {
		if isBlockedWebhookIP(parsedIP) {
			return nil, fmt.Errorf("%w: webhook host must resolve to a public IP", domain.ErrInvalidInput)
		}
		return []net.IP{parsedIP}, nil
	}

	addrs, err := w.resolver.LookupIPAddr(ctx, trimmedHost)
	if err != nil {
		return nil, fmt.Errorf("%w: webhook host could not be resolved", domain.ErrInvalidInput)
	}

	allowed := make([]net.IP, 0, len(addrs))
	seen := make(map[string]struct{}, len(addrs))
	for _, addr := range addrs {
		if isBlockedWebhookIP(addr.IP) {
			continue
		}
		key := addr.IP.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		allowed = append(allowed, addr.IP)
	}
	if len(allowed) == 0 {
		return nil, fmt.Errorf("%w: webhook host must resolve to a public IP", domain.ErrInvalidInput)
	}

	return allowed, nil
}

func isBlockedWebhookIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}

	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	return carrierGradeNATPrefix.Contains(addr.Unmap())
}

func generateWebhookSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "whsec_" + hex.EncodeToString(b), nil
}

func computeHMAC(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
