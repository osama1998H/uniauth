package service

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	db "github.com/osama1998h/uniauth/internal/repository/postgres"
)

// WebhookService dispatches webhook events to registered endpoints.
type WebhookService struct {
	store  *db.Store
	logger *slog.Logger
	client *http.Client
}

// NewWebhookService creates a WebhookService.
func NewWebhookService(store *db.Store, logger *slog.Logger) *WebhookService {
	return &WebhookService{
		store:  store,
		logger: logger,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Dispatch fires webhook events for a given org+event asynchronously.
func (w *WebhookService) Dispatch(orgID uuid.UUID, event string, payload any) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		hooks, err := w.store.ListActiveWebhooksForEvent(ctx, orgID, event)
		if err != nil {
			w.logger.Error("webhook: list hooks", "error", err)
			return
		}
		for _, hook := range hooks {
			w.deliver(hook.URL, hook.Secret, event, payload)
		}
	}()
}

func (w *WebhookService) deliver(url, secret, event string, payload any) {
	body, err := json.Marshal(map[string]any{
		"event":      event,
		"data":       payload,
		"delivered_at": time.Now().UTC(),
	})
	if err != nil {
		w.logger.Error("webhook: marshal payload", "error", err)
		return
	}

	sig := computeHMAC(secret, body)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		w.logger.Error("webhook: build request", "error", err, "url", url)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-UniAuth-Signature", "sha256="+sig)
	req.Header.Set("X-UniAuth-Event", event)

	resp, err := w.client.Do(req)
	if err != nil {
		w.logger.Warn("webhook: delivery failed", "url", url, "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		w.logger.Warn("webhook: non-2xx response", "url", url, "status", resp.StatusCode)
	}
}

func computeHMAC(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
