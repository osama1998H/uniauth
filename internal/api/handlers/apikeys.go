package handlers

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/osama1998h/uniauth/internal/api/middleware"
	"github.com/osama1998h/uniauth/internal/service"
)

// APIKeyHandler handles API key management endpoints.
type APIKeyHandler struct {
	apiKeySvc *service.APIKeyService
}

// NewAPIKeyHandler creates an APIKeyHandler.
func NewAPIKeyHandler(apiKeySvc *service.APIKeyService) *APIKeyHandler {
	return &APIKeyHandler{apiKeySvc: apiKeySvc}
}

// ListAPIKeys godoc
// GET /api/v1/api-keys
func (h *APIKeyHandler) ListAPIKeys(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.GetOrgID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	keys, err := h.apiKeySvc.List(r.Context(), orgID)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	resp := make([]map[string]any, len(keys))
	for i, k := range keys {
		resp[i] = apiKeyResponse(k)
	}
	writeJSON(w, http.StatusOK, map[string]any{"api_keys": resp})
}

// CreateAPIKey godoc
// POST /api/v1/api-keys
func (h *APIKeyHandler) CreateAPIKey(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.GetOrgID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	actorID, _ := middleware.GetUserID(r.Context())

	var req struct {
		Name      string     `json:"name"`
		Scopes    []string   `json:"scopes"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if err := decodeJSON(r, &req); err != nil || req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	out, err := h.apiKeySvc.Create(r.Context(), service.CreateAPIKeyInput{
		OrgID:     orgID,
		Name:      req.Name,
		Scopes:    req.Scopes,
		ExpiresAt: req.ExpiresAt,
	}, actorID)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	// Include the plaintext key in the response — shown only once
	resp := apiKeyResponse(out.APIKey)
	resp["key"] = out.PlaintextKey
	writeJSON(w, http.StatusCreated, resp)
}

// RevokeAPIKey godoc
// DELETE /api/v1/api-keys/{id}
func (h *APIKeyHandler) RevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	keyID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid api key id")
		return
	}
	orgID, _ := middleware.GetOrgID(r.Context())
	actorID, _ := middleware.GetUserID(r.Context())

	if err := h.apiKeySvc.Revoke(r.Context(), keyID, orgID, actorID); err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "api key revoked"})
}
