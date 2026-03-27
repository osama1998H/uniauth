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
// GET /api/v1/users/me
func (h *UserHandler) GetMe(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	user, err := h.userSvc.GetByID(r.Context(), userID)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, userResponse(user))
}

// UpdateMe godoc
// PUT /api/v1/users/me
func (h *UserHandler) UpdateMe(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
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

	user, err := h.userSvc.UpdateProfile(r.Context(), userID, service.UpdateProfileInput{
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
// GET /api/v1/users
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
// GET /api/v1/users/{id}
func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	user, err := h.userSvc.GetByID(r.Context(), id)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, userResponse(user))
}

// DeactivateUser godoc
// DELETE /api/v1/users/{id}
func (h *UserHandler) DeactivateUser(w http.ResponseWriter, r *http.Request) {
	actorID, ok := middleware.GetUserID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	targetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	if err := h.userSvc.Deactivate(r.Context(), actorID, targetID); err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "user deactivated"})
}
