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

// Live godoc
// @Summary     Liveness probe
// @Description Returns 200 OK when the server process is running. Used by Kubernetes liveness probes.
// @Tags        Health
// @Produce     json
// @Success     200 {object} map[string]string "ok"
// @Router      /health [get]
func (h *HealthHandler) Live(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Ready godoc
// @Summary     Readiness probe
// @Description Checks database and Redis connectivity. Returns 503 if either dependency is unavailable.
// @Tags        Health
// @Produce     json
// @Success     200 {object} HealthReadyResponse
// @Failure     503 {object} HealthReadyResponse
// @Router      /ready [get]
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
