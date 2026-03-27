package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/osama1998h/uniauth/internal/api/middleware"
	"github.com/osama1998h/uniauth/internal/service"
	"github.com/osama1998h/uniauth/internal/testutil"
)

func TestWebhookHandlerCreateWebhookRejectsUnsafeURL(t *testing.T) {
	handler := NewWebhookHandler(service.NewWebhookService(nil, testutil.DiscardLogger()))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks", strings.NewReader(`{"url":"https://127.0.0.1/hooks","events":["user.login"]}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.ContextKeyOrgID, uuid.New()))

	rec := httptest.NewRecorder()
	handler.CreateWebhook(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["error"] == "" {
		t.Fatal("expected error body")
	}
}

func TestWebhookHandlerUpdateWebhookRejectsUnsafeURL(t *testing.T) {
	handler := NewWebhookHandler(service.NewWebhookService(nil, testutil.DiscardLogger()))

	req := httptest.NewRequest(http.MethodPut, "/api/v1/webhooks/"+uuid.NewString(), strings.NewReader(`{"url":"https://127.0.0.1/hooks"}`))
	req.Header.Set("Content-Type", "application/json")

	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("id", uuid.NewString())
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx)
	ctx = context.WithValue(ctx, middleware.ContextKeyOrgID, uuid.New())
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	handler.UpdateWebhook(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["error"] == "" {
		t.Fatal("expected error body")
	}
}
