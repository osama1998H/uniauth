package handlers

import (
	"net/http"

	"github.com/osama1998h/uniauth/internal/api/middleware"
	"github.com/osama1998h/uniauth/internal/service"
)

// AuthHandler handles authentication endpoints.
type AuthHandler struct {
	authSvc *service.AuthService
}

// NewAuthHandler creates an AuthHandler.
func NewAuthHandler(authSvc *service.AuthService) *AuthHandler {
	return &AuthHandler{authSvc: authSvc}
}

// Register godoc
// POST /api/v1/auth/register
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OrgName  string  `json:"org_name"`
		Email    string  `json:"email"`
		Password string  `json:"password"`
		FullName *string `json:"full_name"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.OrgName == "" || req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "org_name, email, and password are required")
		return
	}

	ip := ptrStr(middleware.RealIPFromRequest(r))
	ua := ptrStr(r.UserAgent())

	out, err := h.authSvc.Register(r.Context(), service.RegisterInput{
		OrgName:  req.OrgName,
		Email:    req.Email,
		Password: req.Password,
		FullName: req.FullName,
	}, ip, ua)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"organization": orgResponse(out.Org),
		"user":         userResponse(out.User),
	})
}

// Login godoc
// POST /api/v1/auth/login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OrgSlug  string `json:"org_slug"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.OrgSlug == "" || req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "org_slug, email, and password are required")
		return
	}

	ip := ptrStr(middleware.RealIPFromRequest(r))
	ua := ptrStr(r.UserAgent())

	pair, user, err := h.authSvc.Login(r.Context(), service.LoginInput{
		OrgSlug:   req.OrgSlug,
		Email:     req.Email,
		Password:  req.Password,
		UserAgent: ua,
		IPAddress: ip,
	})
	if err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":             pair.AccessToken,
		"refresh_token":            pair.RefreshToken,
		"access_token_expires_at":  pair.AccessTokenExpiresAt,
		"refresh_token_expires_at": pair.RefreshTokenExpiresAt,
		"user":                     userResponse(user),
	})
}

// Refresh godoc
// POST /api/v1/auth/refresh
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := decodeJSON(r, &req); err != nil || req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "refresh_token is required")
		return
	}

	ip := ptrStr(middleware.RealIPFromRequest(r))
	ua := ptrStr(r.UserAgent())

	pair, _, err := h.authSvc.Refresh(r.Context(), req.RefreshToken, ua, ip)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":             pair.AccessToken,
		"refresh_token":            pair.RefreshToken,
		"access_token_expires_at":  pair.AccessTokenExpiresAt,
		"refresh_token_expires_at": pair.RefreshTokenExpiresAt,
	})
}

// Logout godoc
// POST /api/v1/auth/logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := decodeJSON(r, &req); err != nil || req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "refresh_token is required")
		return
	}

	tokenID, _ := middleware.GetTokenID(r.Context())
	tokenExpiry, _ := middleware.GetTokenExpiry(r.Context())

	if err := h.authSvc.Logout(r.Context(), req.RefreshToken, tokenID, tokenExpiry); err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "logged out successfully"})
}

// LogoutAll godoc
// POST /api/v1/auth/logout-all
func (h *AuthHandler) LogoutAll(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	tokenID, _ := middleware.GetTokenID(r.Context())
	tokenExpiry, _ := middleware.GetTokenExpiry(r.Context())

	if err := h.authSvc.LogoutAll(r.Context(), userID, tokenID, tokenExpiry); err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "all sessions revoked"})
}

// RequestPasswordReset godoc
// POST /api/v1/auth/password/reset-request
func (h *AuthHandler) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OrgSlug string `json:"org_slug"`
		Email   string `json:"email"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ip := ptrStr(middleware.RealIPFromRequest(r))
	ua := ptrStr(r.UserAgent())

	// Always respond 200 to prevent email enumeration
	_ = h.authSvc.RequestPasswordReset(r.Context(), req.OrgSlug, req.Email, ip, ua)
	writeJSON(w, http.StatusOK, map[string]string{"message": "if the account exists, a reset email has been sent"})
}

// ConfirmPasswordReset godoc
// POST /api/v1/auth/password/reset-confirm
func (h *AuthHandler) ConfirmPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Token == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "token and password are required")
		return
	}

	if err := h.authSvc.ConfirmPasswordReset(r.Context(), req.Token, req.Password); err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "password reset successfully"})
}

// ChangePassword godoc
// PUT /api/v1/auth/password/change
func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.CurrentPassword == "" || req.NewPassword == "" {
		writeError(w, http.StatusBadRequest, "current_password and new_password are required")
		return
	}

	tokenID, _ := middleware.GetTokenID(r.Context())
	tokenExpiry, _ := middleware.GetTokenExpiry(r.Context())

	if err := h.authSvc.ChangePassword(r.Context(), userID, req.CurrentPassword, req.NewPassword, tokenID, tokenExpiry); err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "password changed successfully"})
}

func ptrStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
