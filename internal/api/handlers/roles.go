package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/osama1998h/uniauth/internal/api/middleware"
	"github.com/osama1998h/uniauth/internal/service"
)

// RoleHandler handles RBAC endpoints.
type RoleHandler struct {
	rbacSvc *service.RBACService
}

// NewRoleHandler creates a RoleHandler.
func NewRoleHandler(rbacSvc *service.RBACService) *RoleHandler {
	return &RoleHandler{rbacSvc: rbacSvc}
}

// ListPermissions godoc
// GET /api/v1/roles/permissions
func (h *RoleHandler) ListPermissions(w http.ResponseWriter, r *http.Request) {
	perms, err := h.rbacSvc.ListPermissions(r.Context())
	if err != nil {
		handleServiceError(w, err)
		return
	}
	resp := make([]map[string]any, len(perms))
	for i, p := range perms {
		resp[i] = permissionResponse(p)
	}
	writeJSON(w, http.StatusOK, map[string]any{"permissions": resp})
}

// ListRoles godoc
// GET /api/v1/roles
func (h *RoleHandler) ListRoles(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.GetOrgID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	roles, err := h.rbacSvc.ListRoles(r.Context(), orgID)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	resp := make([]map[string]any, len(roles))
	for i, ro := range roles {
		resp[i] = roleResponse(ro)
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": resp})
}

// CreateRole godoc
// POST /api/v1/roles
func (h *RoleHandler) CreateRole(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.GetOrgID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	actorID, _ := middleware.GetUserID(r.Context())

	var req struct {
		Name        string  `json:"name"`
		Description *string `json:"description"`
	}
	if err := decodeJSON(r, &req); err != nil || req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	role, err := h.rbacSvc.CreateRole(r.Context(), orgID, req.Name, req.Description, actorID)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, roleResponse(role))
}

// UpdateRole godoc
// PUT /api/v1/roles/{id}
func (h *RoleHandler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	roleID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid role id")
		return
	}

	var req struct {
		Name        string  `json:"name"`
		Description *string `json:"description"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	role, err := h.rbacSvc.UpdateRole(r.Context(), roleID, req.Name, req.Description)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, roleResponse(role))
}

// DeleteRole godoc
// DELETE /api/v1/roles/{id}
func (h *RoleHandler) DeleteRole(w http.ResponseWriter, r *http.Request) {
	roleID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid role id")
		return
	}
	actorID, _ := middleware.GetUserID(r.Context())
	orgID, _ := middleware.GetOrgID(r.Context())

	if err := h.rbacSvc.DeleteRole(r.Context(), roleID, actorID, orgID); err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "role deleted"})
}

// AssignPermissions godoc
// POST /api/v1/roles/{id}/permissions
func (h *RoleHandler) AssignPermissions(w http.ResponseWriter, r *http.Request) {
	roleID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid role id")
		return
	}

	var req struct {
		Permissions []string `json:"permissions"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.rbacSvc.AssignPermissions(r.Context(), roleID, req.Permissions); err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "permissions assigned"})
}

// AssignRoleToUser godoc
// POST /api/v1/users/{id}/roles
func (h *RoleHandler) AssignRoleToUser(w http.ResponseWriter, r *http.Request) {
	targetUserID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	actorID, _ := middleware.GetUserID(r.Context())
	orgID, _ := middleware.GetOrgID(r.Context())

	var req struct {
		RoleID uuid.UUID `json:"role_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.rbacSvc.AssignRoleToUser(r.Context(), targetUserID, req.RoleID, actorID, orgID); err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "role assigned"})
}
