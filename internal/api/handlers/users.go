package handlers

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/osama1998h/uniauth/internal/api/middleware"
	"github.com/osama1998h/uniauth/internal/service"
)

// UserHandler handles user management endpoints.
type UserHandler struct {
	userSvc *service.UserService
}

// NewUserHandler creates a UserHandler.
func NewUserHandler(userSvc *service.UserService) *UserHandler {
	return &UserHandler{userSvc: userSvc}
}

// GetMe godoc
// @Summary     Get current user profile
// @Description Returns the profile of the currently authenticated user.
// @Tags        Users
// @Produce     json
// @Success     200 {object} UserView
// @Failure     401 {object} SwaggerErrorResponse
// @Failure     500 {object} SwaggerErrorResponse
// @Security    BearerAuth
// @Router      /api/v1/users/me [get]
func (h *UserHandler) GetMe(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	orgID, ok := middleware.GetOrgID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	user, err := h.userSvc.GetByID(r.Context(), orgID, userID)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, userResponse(user))
}

// UpdateMe godoc
// @Summary     Update current user profile
// @Description Updates the full name and/or email of the currently authenticated user.
// @Tags        Users
// @Accept      json
// @Produce     json
// @Param       body body UpdateMeRequest true "Fields to update"
// @Success     200 {object} UserView
// @Failure     400 {object} SwaggerErrorResponse
// @Failure     401 {object} SwaggerErrorResponse
// @Failure     409 {object} SwaggerErrorResponse "Email already in use"
// @Failure     500 {object} SwaggerErrorResponse
// @Security    BearerAuth
// @Router      /api/v1/users/me [put]
func (h *UserHandler) UpdateMe(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	orgID, ok := middleware.GetOrgID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req struct {
		FullName *string `json:"full_name"`
		Email    *string `json:"email"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	user, err := h.userSvc.UpdateProfile(r.Context(), orgID, userID, service.UpdateProfileInput{
		FullName: req.FullName,
		Email:    req.Email,
	})
	if err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, userResponse(user))
}

// ListUsers godoc
// @Summary     List users in organization
// @Description Returns a paginated list of all users in the authenticated user's organization.
// @Tags        Users
// @Produce     json
// @Param       limit  query int false "Maximum number of results (default 50, max 100)"
// @Param       offset query int false "Number of results to skip"
// @Success     200 {object} UserListResponse
// @Failure     401 {object} SwaggerErrorResponse
// @Failure     500 {object} SwaggerErrorResponse
// @Security    BearerAuth
// @Router      /api/v1/users [get]
func (h *UserHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.GetOrgID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	users, err := h.userSvc.ListByOrg(r.Context(), orgID, limit, offset)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	resp := make([]map[string]any, len(users))
	for i, u := range users {
		resp[i] = userResponse(u)
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": resp, "limit": limit, "offset": offset})
}

// GetUser godoc
// @Summary     Get user by ID
// @Description Returns the profile of a specific user within the organization.
// @Tags        Users
// @Produce     json
// @Param       id path string true "User UUID"
// @Success     200 {object} UserView
// @Failure     400 {object} SwaggerErrorResponse "Invalid UUID"
// @Failure     401 {object} SwaggerErrorResponse
// @Failure     404 {object} SwaggerErrorResponse
// @Failure     500 {object} SwaggerErrorResponse
// @Security    BearerAuth
// @Router      /api/v1/users/{id} [get]
func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.GetOrgID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	user, err := h.userSvc.GetByID(r.Context(), orgID, id)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, userResponse(user))
}

// DeactivateUser godoc
// @Summary     Deactivate a user
// @Description Marks the specified user as inactive. Deactivated users cannot log in.
// @Tags        Users
// @Produce     json
// @Param       id path string true "User UUID"
// @Success     200 {object} SwaggerMessageResponse
// @Failure     400 {object} SwaggerErrorResponse "Invalid UUID"
// @Failure     401 {object} SwaggerErrorResponse
// @Failure     404 {object} SwaggerErrorResponse
// @Failure     500 {object} SwaggerErrorResponse
// @Security    BearerAuth
// @Router      /api/v1/users/{id} [delete]
func (h *UserHandler) DeactivateUser(w http.ResponseWriter, r *http.Request) {
	actorID, ok := middleware.GetUserID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	orgID, ok := middleware.GetOrgID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	targetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	if err := h.userSvc.Deactivate(r.Context(), orgID, actorID, targetID); err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "user deactivated"})
}
