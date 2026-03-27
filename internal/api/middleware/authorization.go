package middleware

import (
	"context"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/osama1998h/uniauth/internal/domain"
)

type permissionAuthorizer interface {
	Authorize(ctx context.Context, orgID, userID uuid.UUID, permission string) error
}

// RequirePermission ensures the authenticated user has the requested permission.
func RequirePermission(authorizer permissionAuthorizer, permission string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := GetUserID(r.Context())
			if !ok {
				writeUnauthorized(w, "unauthorized")
				return
			}
			orgID, ok := GetOrgID(r.Context())
			if !ok {
				writeUnauthorized(w, "unauthorized")
				return
			}

			if err := authorizer.Authorize(r.Context(), orgID, userID, permission); err != nil {
				switch {
				case errors.Is(err, domain.ErrForbidden):
					writeForbidden(w, "forbidden")
				case errors.Is(err, domain.ErrUnauthorized):
					writeUnauthorized(w, "unauthorized")
				default:
					writeInternalError(w)
				}
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func writeForbidden(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"error":"` + msg + `"}`))
}

func writeInternalError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write([]byte(`{"error":"internal server error"}`))
}
