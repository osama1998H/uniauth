// @title           UniAuth API
// @version         1.0
// @description     Self-hosted, multi-tenant authentication and authorization service. Provides JWT-based auth, RBAC, API keys, audit logging, and webhook event delivery.
// @termsOfService  http://swagger.io/terms/

// @contact.name   UniAuth Support
// @contact.url    https://github.com/osama1998h/uniauth

// @license.name  MIT
// @license.url   https://opensource.org/licenses/MIT

// @host      localhost:8080
// @BasePath  /

// @securityDefinitions.apikey  BearerAuth
// @in                          header
// @name                        Authorization
// @description                 Type "Bearer " followed by your JWT access token. Example: "Bearer eyJhbGci..."

// @securityDefinitions.apikey  ApiKeyAuth
// @in                          header
// @name                        X-API-Key
// @description                 API key for service-to-service authentication.

// @tag.name         Health
// @tag.description  Liveness and readiness probes

// @tag.name         Auth
// @tag.description  Registration, login, token management, and password operations

// @tag.name         Users
// @tag.description  User profile and user management within an organization

// @tag.name         Organizations
// @tag.description  Organization profile management

// @tag.name         Roles
// @tag.description  RBAC role and permission management

// @tag.name         API Keys
// @tag.description  API key lifecycle management

// @tag.name         Audit
// @tag.description  Audit log retrieval

// @tag.name         Webhooks
// @tag.description  Webhook endpoint management

package main

import (
	_ "github.com/osama1998h/uniauth/docs"

	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"

	"github.com/osama1998h/uniauth/internal/api"
	"github.com/osama1998h/uniauth/internal/config"
	"github.com/osama1998h/uniauth/internal/repository/cache"
	db "github.com/osama1998h/uniauth/internal/repository/postgres"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	cfg, err := config.Load()
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	if cfg.IsDevelopment() {
		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Database
	store, err := db.New(ctx, cfg.Database.URL)
	if err != nil {
		logger.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer store.Close()
	logger.Info("database connected")

	// Run migrations
	if err := runMigrations(cfg.Database.URL, logger); err != nil {
		logger.Error("migration failed", "error", err)
		os.Exit(1)
	}

	// Redis
	redisCache, err := cache.New(ctx, cfg.Redis.URL)
	if err != nil {
		logger.Error("failed to connect to redis", "error", err)
		os.Exit(1)
	}
	defer func() { _ = redisCache.Close() }()
	logger.Info("redis connected")

	// JWT secret validation
	if cfg.Auth.JWTSecret == "" {
		logger.Error("JWT_SECRET must be set")
		os.Exit(1)
	}

	// HTTP server
	handler := api.NewRouter(cfg, store, redisCache, logger)
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		logger.Info("server starting", "port", cfg.Server.Port, "env", cfg.Server.Environment)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	<-quit
	logger.Info("shutting down server")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("server forced shutdown", "error", err)
		os.Exit(1)
	}

	logger.Info("server stopped")
}

func runMigrations(databaseURL string, logger *slog.Logger) error {
	m, err := migrate.New("file://migrations", databaseURL)
	if err != nil {
		return fmt.Errorf("create migrator: %w", err)
	}
	defer func() { _, _ = m.Close() }()

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("run migrations: %w", err)
	}

	logger.Info("migrations applied")
	return nil
}
