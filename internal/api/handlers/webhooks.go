package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/osama1998h/uniauth/internal/api/middleware"
	db "github.com/osama1998h/uniauth/internal/repository/postgres"
)

// WebhookHandler handles webhook management endpoints.
type WebhookHandler struct {
	store *db.Store
}

// NewWebhookHandler creates a WebhookHandler.
func NewWebhookHandler(store *db.Store) *WebhookHandler {
	return &WebhookHandler{store: store}
}

// ListWebhooks godoc
// @Summary     List webhooks
// @Description Returns all webhook endpoints configured for the authenticated user's organization.
// @Tags        Webhooks
// @Produce     json
// @Success     200 {object} WebhookListResponse
// @Failure     401 {object} SwaggerErrorResponse
// @Failure     500 {object} SwaggerErrorResponse
// @Security    BearerAuth
// @Router      /api/v1/webhooks [get]
func (h *WebhookHandler) ListWebhooks(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.GetOrgID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	hooks, err := h.store.ListWebhooksByOrg(r.Context(), orgID)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	resp := make([]map[string]any, len(hooks))
	for i, wh := range hooks {
		resp[i] = webhookResponse(wh)
	}
	writeJSON(w, http.StatusOK, map[string]any{"webhooks": resp})
}

// CreateWebhook godoc
// @Summary     Create a webhook
// @Description Registers a new webhook endpoint. The HMAC signing secret is returned only in this response — store it securely.
// @Tags        Webhooks
// @Accept      json
// @Produce     json
// @Param       body body CreateWebhookRequest true "Webhook configuration"
// @Success     201 {object} CreateWebhookResponse
// @Failure     400 {object} SwaggerErrorResponse
// @Failure     401 {object} SwaggerErrorResponse
// @Failure     500 {object} SwaggerErrorResponse
// @Security    BearerAuth
// @Router      /api/v1/webhooks [post]
func (h *WebhookHandler) CreateWebhook(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.GetOrgID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req struct {
		URL    string   `json:"url"`
		Events []string `json:"events"`
	}
	if err := decodeJSON(r, &req); err != nil || req.URL == "" || len(req.Events) == 0 {
		writeError(w, http.StatusBadRequest, "url and events are required")
		return
	}

	secret, err := generateSecret()
	if err != nil {
		handleServiceError(w, err)
		return
	}

	wh, err := h.store.CreateWebhook(r.Context(), orgID, req.URL, req.Events, secret)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	resp := webhookResponse(wh)
	resp["secret"] = secret // shown once
	writeJSON(w, http.StatusCreated, resp)
}

// UpdateWebhook godoc
// @Summary     Update a webhook
// @Description Updates the URL, event subscriptions, and/or active status of a webhook.
// @Tags        Webhooks
// @Accept      json
// @Produce     json
// @Param       id   path string              true "Webhook UUID"
// @Param       body body UpdateWebhookRequest true "Fields to update"
// @Success     200 {object} WebhookView
// @Failure     400 {object} SwaggerErrorResponse
// @Failure     401 {object} SwaggerErrorResponse
// @Failure     404 {object} SwaggerErrorResponse
// @Failure     500 {object} SwaggerErrorResponse
// @Security    BearerAuth
// @Router      /api/v1/webhooks/{id} [put]
func (h *WebhookHandler) UpdateWebhook(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid webhook id")
		return
	}
	orgID, _ := middleware.GetOrgID(r.Context())

	var req struct {
		URL      *string  `json:"url"`
		Events   []string `json:"events"`
		IsActive *bool    `json:"is_active"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	wh, err := h.store.UpdateWebhook(r.Context(), id, orgID, req.URL, req.Events, req.IsActive)
	if err != nil || wh == nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, webhookResponse(wh))
}

// DeleteWebhook godoc
// @Summary     Delete a webhook
// @Description Permanently removes the specified webhook endpoint.
// @Tags        Webhooks
// @Produce     json
// @Param       id path string true "Webhook UUID"
// @Success     200 {object} SwaggerMessageResponse
// @Failure     400 {object} SwaggerErrorResponse "Invalid UUID"
// @Failure     401 {object} SwaggerErrorResponse
// @Failure     404 {object} SwaggerErrorResponse
// @Failure     500 {object} SwaggerErrorResponse
// @Security    BearerAuth
// @Router      /api/v1/webhooks/{id} [delete]
func (h *WebhookHandler) DeleteWebhook(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid webhook id")
		return
	}
	orgID, _ := middleware.GetOrgID(r.Context())

	if err := h.store.DeleteWebhook(r.Context(), id, orgID); err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "webhook deleted"})
}

func webhookResponse(wh *db.Webhook) map[string]any {
	return map[string]any{
		"id":         wh.ID,
		"org_id":     wh.OrgID,
		"url":        wh.URL,
		"events":     wh.Events,
		"is_active":  wh.IsActive,
		"created_at": wh.CreatedAt,
	}
}

func generateSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "whsec_" + hex.EncodeToString(b), nil
}
