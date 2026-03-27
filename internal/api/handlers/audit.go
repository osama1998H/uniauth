package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/osama1998h/uniauth/internal/api/middleware"
	"github.com/osama1998h/uniauth/internal/domain"
	db "github.com/osama1998h/uniauth/internal/repository/postgres"
)

// AuditHandler handles audit log endpoints.
type AuditHandler struct {
	store *db.Store
}

// NewAuditHandler creates an AuditHandler.
func NewAuditHandler(store *db.Store) *AuditHandler {
	return &AuditHandler{store: store}
}

// ListAuditLogs godoc
// @Summary     List audit logs
// @Description Returns audit log entries for the authenticated user's organization, with optional filters. Requires the `audit:read` permission.
// @Tags        Audit
// @Produce     json
// @Param       limit   query int    false "Maximum number of results"
// @Param       offset  query int    false "Number of results to skip"
// @Param       user_id query string false "Filter by user UUID"
// @Param       action  query string false "Filter by action (e.g. user.login)"
// @Param       since   query string false "Filter entries after this timestamp (RFC3339)"
// @Param       until   query string false "Filter entries before this timestamp (RFC3339)"
// @Success     200 {object} AuditListResponse
// @Failure     401 {object} SwaggerErrorResponse
// @Failure     403 {object} SwaggerErrorResponse
// @Failure     500 {object} SwaggerErrorResponse
// @Security    BearerAuth
// @Router      /api/v1/audit [get]
func (h *AuditHandler) ListAuditLogs(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.GetOrgID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	filter := domain.AuditFilter{}

	if v := r.URL.Query().Get("limit"); v != "" {
		limit, _ := strconv.Atoi(v)
		filter.Limit = limit
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		offset, _ := strconv.Atoi(v)
		filter.Offset = offset
	}
	if v := r.URL.Query().Get("user_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			filter.UserID = &id
		}
	}
	if v := r.URL.Query().Get("action"); v != "" {
		filter.Action = &v
	}
	if v := r.URL.Query().Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.Since = &t
		}
	}
	if v := r.URL.Query().Get("until"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.Until = &t
		}
	}

	logs, err := h.store.ListAuditLogs(r.Context(), orgID, filter)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	resp := make([]map[string]any, len(logs))
	for i, l := range logs {
		resp[i] = map[string]any{
			"id":            l.ID,
			"org_id":        l.OrgID,
			"user_id":       l.UserID,
			"action":        l.Action,
			"resource_type": l.ResourceType,
			"resource_id":   l.ResourceID,
			"metadata":      l.Metadata,
			"ip_address":    l.IPAddress,
			"user_agent":    l.UserAgent,
			"created_at":    l.CreatedAt,
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"logs": resp, "count": len(logs)})
}
