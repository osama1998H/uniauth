package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/osama1998h/uniauth/internal/domain"
	"github.com/osama1998h/uniauth/internal/service"
	"github.com/osama1998h/uniauth/pkg/token"
)

type contextKey string

const (
	ContextKeyUserID contextKey = "user_id"
	ContextKeyOrgID  contextKey = "org_id"
)

// JWTAuth extracts and validates a Bearer JWT from the Authorization header.
func JWTAuth(maker *token.Maker) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr := extractBearer(r)
			if tokenStr == "" {
				writeUnauthorized(w, "missing authorization header")
				return
			}

			claims, err := maker.Verify(tokenStr)
			if err != nil {
				writeUnauthorized(w, "invalid or expired token")
				return
			}

			ctx := context.WithValue(r.Context(), ContextKeyUserID, claims.UserID)
			ctx = context.WithValue(ctx, ContextKeyOrgID, claims.OrgID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// APIKeyAuth validates an API key from the X-API-Key header.
func APIKeyAuth(apiKeySvc *service.APIKeyService) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := r.Header.Get("X-API-Key")
			if key == "" {
				writeUnauthorized(w, "missing X-API-Key header")
				return
			}

			apiKey, err := apiKeySvc.ValidateAPIKey(r.Context(), key)
			if err != nil {
				if err == domain.ErrAPIKeyRevoked {
					writeUnauthorized(w, "api key has been revoked")
				} else {
					writeUnauthorized(w, "invalid api key")
				}
				return
			}

			ctx := context.WithValue(r.Context(), ContextKeyOrgID, apiKey.OrgID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetUserID retrieves the authenticated user ID from the context.
func GetUserID(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(ContextKeyUserID).(uuid.UUID)
	return id, ok
}

// GetOrgID retrieves the authenticated org ID from the context.
func GetOrgID(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(ContextKeyOrgID).(uuid.UUID)
	return id, ok
}

func extractBearer(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(auth, "Bearer ")
}

func writeUnauthorized(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"` + msg + `"}`))
}
