package handlers

import (
	"net/http"

	db "github.com/osama1998h/uniauth/internal/repository/postgres"
	"github.com/osama1998h/uniauth/internal/repository/cache"
)

// HealthHandler handles health and readiness checks.
type HealthHandler struct {
	store *db.Store
	cache *cache.Cache
}

// NewHealthHandler creates a HealthHandler.
func NewHealthHandler(store *db.Store, redisCache *cache.Cache) *HealthHandler {
	return &HealthHandler{store: store, cache: redisCache}
}

// Live returns 200 OK — used for Kubernetes liveness probe.
func (h *HealthHandler) Live(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Ready checks database and Redis connectivity — used for readiness probe.
func (h *HealthHandler) Ready(w http.ResponseWriter, r *http.Request) {
	checks := map[string]string{
		"database": "ok",
		"cache":    "ok",
	}
	status := http.StatusOK

	if err := h.store.Ping(r.Context()); err != nil {
		checks["database"] = "error: " + err.Error()
		status = http.StatusServiceUnavailable
	}
	if err := h.cache.Ping(r.Context()); err != nil {
		checks["cache"] = "error: " + err.Error()
		status = http.StatusServiceUnavailable
	}

	writeJSON(w, status, map[string]any{"status": map[string]string(checks)})
}
