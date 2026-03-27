package handlers

import (
	"net/http"

	"github.com/osama1998h/uniauth/internal/api/middleware"
	"github.com/osama1998h/uniauth/internal/service"
)

// OrgHandler handles organization endpoints.
type OrgHandler struct {
	orgSvc *service.OrgService
}

// NewOrgHandler creates an OrgHandler.
func NewOrgHandler(orgSvc *service.OrgService) *OrgHandler {
	return &OrgHandler{orgSvc: orgSvc}
}

// GetMyOrg godoc
// @Summary     Get current organization
// @Description Returns the organization associated with the authenticated user's JWT.
// @Tags        Organizations
// @Produce     json
// @Success     200 {object} OrgView
// @Failure     401 {object} SwaggerErrorResponse
// @Failure     404 {object} SwaggerErrorResponse
// @Failure     500 {object} SwaggerErrorResponse
// @Security    BearerAuth
// @Router      /api/v1/organizations/me [get]
func (h *OrgHandler) GetMyOrg(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.GetOrgID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	org, err := h.orgSvc.GetByID(r.Context(), orgID)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, orgResponse(org))
}

// UpdateMyOrg godoc
// @Summary     Update current organization
// @Description Updates the name of the authenticated user's organization.
// @Tags        Organizations
// @Accept      json
// @Produce     json
// @Param       body body UpdateOrgRequest true "New organization name"
// @Success     200 {object} OrgView
// @Failure     400 {object} SwaggerErrorResponse
// @Failure     401 {object} SwaggerErrorResponse
// @Failure     500 {object} SwaggerErrorResponse
// @Security    BearerAuth
// @Router      /api/v1/organizations/me [put]
func (h *OrgHandler) UpdateMyOrg(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.GetOrgID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &req); err != nil || req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	org, err := h.orgSvc.Update(r.Context(), orgID, req.Name)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, orgResponse(org))
}
