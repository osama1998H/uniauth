package api

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	httpSwagger "github.com/swaggo/http-swagger/v2"

	"github.com/osama1998h/uniauth/internal/api/handlers"
	"github.com/osama1998h/uniauth/internal/api/middleware"
	"github.com/osama1998h/uniauth/internal/config"
	"github.com/osama1998h/uniauth/internal/domain"
	"github.com/osama1998h/uniauth/internal/repository/cache"
	db "github.com/osama1998h/uniauth/internal/repository/postgres"
	"github.com/osama1998h/uniauth/internal/service"
	"github.com/osama1998h/uniauth/pkg/token"
)

// NewRouter wires up all dependencies and returns the HTTP handler.
func NewRouter(
	cfg *config.Config,
	store *db.Store,
	redisCache *cache.Cache,
	logger *slog.Logger,
) http.Handler {
	// --- Services ---
	tokenMaker := token.NewMaker(cfg.Auth.JWTSecret, cfg.Auth.AccessTokenDuration, cfg.Auth.RefreshTokenDuration)
	auditSvc := service.NewAuditService(store, logger)
	webhookSvc := service.NewWebhookService(store, logger)
	emailSvc := service.NewEmailService(cfg.Email, logger, cfg.IsDevelopment())
	authSvc := service.NewAuthService(store, tokenMaker, redisCache, auditSvc, webhookSvc, emailSvc, cfg.Auth)
	userSvc := service.NewUserService(store, auditSvc, webhookSvc)
	orgSvc := service.NewOrgService(store)
	rbacSvc := service.NewRBACService(store, auditSvc)
	apiKeySvc := service.NewAPIKeyService(store, auditSvc)

	// --- Handlers ---
	healthH := handlers.NewHealthHandler(store, redisCache)
	authH := handlers.NewAuthHandler(authSvc)
	userH := handlers.NewUserHandler(userSvc)
	orgH := handlers.NewOrgHandler(orgSvc)
	roleH := handlers.NewRoleHandler(rbacSvc)
	apiKeyH := handlers.NewAPIKeyHandler(apiKeySvc)
	auditH := handlers.NewAuditHandler(store)
	webhookH := handlers.NewWebhookHandler(webhookSvc)
	clientIPResolver := middleware.NewClientIPResolver(cfg.Server.TrustedProxyRanges)

	// --- Router ---
	r := chi.NewRouter()

	// Global middleware
	r.Use(chimiddleware.RequestID)
	r.Use(middleware.PopulateClientIP(clientIPResolver))
	r.Use(middleware.Recovery(logger))
	r.Use(middleware.RequestLogger(logger))
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   cfg.AllowedOrigins(),
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-API-Key"},
		AllowCredentials: true,
		MaxAge:           300,
	}))
	r.Use(middleware.RateLimit(redisCache, cfg.Auth.RateLimitPerMinute, logger))

	// Health
	r.Get("/health", healthH.Live)
	r.Get("/ready", healthH.Ready)

	// Swagger UI
	r.Get("/swagger/*", httpSwagger.Handler(
		httpSwagger.URL("/swagger/doc.json"),
	))

	// API v1
	r.Route("/api/v1", func(r chi.Router) {
		// Auth — public
		r.Route("/auth", func(r chi.Router) {
			r.Post("/register", authH.Register)
			r.Post("/login", authH.Login)
			r.Post("/refresh", authH.Refresh)
			r.Post("/password/reset-request", authH.RequestPasswordReset)
			r.Post("/password/reset-confirm", authH.ConfirmPasswordReset)
			r.Post("/email/verify-confirm", authH.ConfirmEmailVerification)

			// Auth — requires JWT
			r.Group(func(r chi.Router) {
				r.Use(middleware.JWTAuth(tokenMaker, redisCache, logger))
				r.Post("/logout", authH.Logout)
				r.Post("/logout-all", authH.LogoutAll)
				r.Put("/password/change", authH.ChangePassword)
				r.Post("/email/verify-request", authH.RequestEmailVerification)
			})
		})

		// All routes below require JWT auth
		r.Group(func(r chi.Router) {
			r.Use(middleware.JWTAuth(tokenMaker, redisCache, logger))

			// Users
			r.Route("/users", func(r chi.Router) {
				r.Get("/me", userH.GetMe)
				r.Put("/me", userH.UpdateMe)
				r.With(middleware.RequirePermission(rbacSvc, domain.PermissionUsersWrite)).Post("/", userH.CreateUser)
				r.With(middleware.RequirePermission(rbacSvc, domain.PermissionUsersRead)).Get("/", userH.ListUsers)
				r.With(middleware.RequirePermission(rbacSvc, domain.PermissionUsersRead)).Get("/{id}", userH.GetUser)
				r.With(middleware.RequirePermission(rbacSvc, domain.PermissionUsersDelete)).Delete("/{id}", userH.DeactivateUser)
				r.With(middleware.RequirePermission(rbacSvc, domain.PermissionRolesWrite)).Post("/{id}/roles", roleH.AssignRoleToUser)
			})

			// Organizations
			r.Route("/organizations", func(r chi.Router) {
				r.With(middleware.RequirePermission(rbacSvc, domain.PermissionOrganizationsRead)).Get("/me", orgH.GetMyOrg)
				r.With(middleware.RequirePermission(rbacSvc, domain.PermissionOrganizationsWrite)).Put("/me", orgH.UpdateMyOrg)
			})

			// Roles & Permissions
			r.Route("/roles", func(r chi.Router) {
				r.With(middleware.RequirePermission(rbacSvc, domain.PermissionRolesRead)).Get("/permissions", roleH.ListPermissions)
				r.With(middleware.RequirePermission(rbacSvc, domain.PermissionRolesRead)).Get("/", roleH.ListRoles)
				r.With(middleware.RequirePermission(rbacSvc, domain.PermissionRolesWrite)).Post("/", roleH.CreateRole)
				r.With(middleware.RequirePermission(rbacSvc, domain.PermissionRolesWrite)).Put("/{id}", roleH.UpdateRole)
				r.With(middleware.RequirePermission(rbacSvc, domain.PermissionRolesDelete)).Delete("/{id}", roleH.DeleteRole)
				r.With(middleware.RequirePermission(rbacSvc, domain.PermissionRolesWrite)).Post("/{id}/permissions", roleH.AssignPermissions)
			})

			// API Keys
			r.Route("/api-keys", func(r chi.Router) {
				r.With(middleware.RequirePermission(rbacSvc, domain.PermissionAPIKeysRead)).Get("/", apiKeyH.ListAPIKeys)
				r.With(middleware.RequirePermission(rbacSvc, domain.PermissionAPIKeysWrite)).Post("/", apiKeyH.CreateAPIKey)
				r.With(middleware.RequirePermission(rbacSvc, domain.PermissionAPIKeysDelete)).Delete("/{id}", apiKeyH.RevokeAPIKey)
			})

			// Audit Logs
			r.With(middleware.RequirePermission(rbacSvc, domain.PermissionAuditRead)).Get("/audit", auditH.ListAuditLogs)

			// Webhooks
			r.Route("/webhooks", func(r chi.Router) {
				r.With(middleware.RequirePermission(rbacSvc, domain.PermissionWebhooksRead)).Get("/", webhookH.ListWebhooks)
				r.With(middleware.RequirePermission(rbacSvc, domain.PermissionWebhooksWrite)).Post("/", webhookH.CreateWebhook)
				r.With(middleware.RequirePermission(rbacSvc, domain.PermissionWebhooksWrite)).Put("/{id}", webhookH.UpdateWebhook)
				r.With(middleware.RequirePermission(rbacSvc, domain.PermissionWebhooksDelete)).Delete("/{id}", webhookH.DeleteWebhook)
			})
		})
	})

	return r
}
