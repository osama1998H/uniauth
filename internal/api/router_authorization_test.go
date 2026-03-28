package api_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/osama1998h/uniauth/internal/api"
	"github.com/osama1998h/uniauth/internal/config"
	"github.com/osama1998h/uniauth/internal/domain"
	db "github.com/osama1998h/uniauth/internal/repository/postgres"
	"github.com/osama1998h/uniauth/internal/testutil"
	"github.com/osama1998h/uniauth/pkg/token"
)

const routerTestJWTSecret = "supersecretkey-at-least-32-chars!!"

func TestRouterRequiresPermissionsOnPrivilegedRoutes(t *testing.T) {
	store := testutil.RequireTestStore(t)
	handler := newTestRouter(store)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	org := testutil.CreateOrganization(t, store, "router-forbidden-org")
	user := testutil.CreateUser(t, store, org.ID, "router-forbidden-user")
	accessToken := issueAccessToken(t, user.ID, org.ID)

	tests := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{name: "create user", method: http.MethodPost, path: "/api/v1/users", body: `{"email":"test@example.com","password":"S3cur3P@ss!"}`},
		{name: "list users", method: http.MethodGet, path: "/api/v1/users"},
		{name: "get user", method: http.MethodGet, path: "/api/v1/users/" + uuid.NewString()},
		{name: "deactivate user", method: http.MethodDelete, path: "/api/v1/users/" + uuid.NewString()},
		{name: "assign role to user", method: http.MethodPost, path: "/api/v1/users/" + uuid.NewString() + "/roles", body: `{"role_id":"` + uuid.NewString() + `"}`},
		{name: "get org", method: http.MethodGet, path: "/api/v1/organizations/me"},
		{name: "update org", method: http.MethodPut, path: "/api/v1/organizations/me", body: `{"name":"Updated Org"}`},
		{name: "list permissions", method: http.MethodGet, path: "/api/v1/roles/permissions"},
		{name: "list roles", method: http.MethodGet, path: "/api/v1/roles"},
		{name: "create role", method: http.MethodPost, path: "/api/v1/roles", body: `{"name":"support"}`},
		{name: "update role", method: http.MethodPut, path: "/api/v1/roles/" + uuid.NewString(), body: `{"name":"support"}`},
		{name: "delete role", method: http.MethodDelete, path: "/api/v1/roles/" + uuid.NewString()},
		{name: "assign permissions", method: http.MethodPost, path: "/api/v1/roles/" + uuid.NewString() + "/permissions", body: `{"permissions":["users:read"]}`},
		{name: "list api keys", method: http.MethodGet, path: "/api/v1/api-keys"},
		{name: "create api key", method: http.MethodPost, path: "/api/v1/api-keys", body: `{"name":"build-bot"}`},
		{name: "revoke api key", method: http.MethodDelete, path: "/api/v1/api-keys/" + uuid.NewString()},
		{name: "list audit logs", method: http.MethodGet, path: "/api/v1/audit"},
		{name: "list webhooks", method: http.MethodGet, path: "/api/v1/webhooks"},
		{name: "create webhook", method: http.MethodPost, path: "/api/v1/webhooks", body: `{"url":"https://example.com/hooks","events":["user.login"]}`},
		{name: "update webhook", method: http.MethodPut, path: "/api/v1/webhooks/" + uuid.NewString(), body: `{"url":"https://example.com/hooks"}`},
		{name: "delete webhook", method: http.MethodDelete, path: "/api/v1/webhooks/" + uuid.NewString()},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := performAuthedRequest(handler, tc.method, tc.path, tc.body, accessToken)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s %s status = %d, want %d, body=%s", tc.method, tc.path, rec.Code, http.StatusForbidden, rec.Body.String())
			}
		})
	}

	_ = ctx
}

func TestRouterAllowsSelfServiceEndpointsWithoutRBACPermissions(t *testing.T) {
	store := testutil.RequireTestStore(t)
	handler := newTestRouter(store)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	org := testutil.CreateOrganization(t, store, "router-self-org")
	user := testutil.CreateUser(t, store, org.ID, "router-self-user")
	accessToken := issueAccessToken(t, user.ID, org.ID)

	getRec := performAuthedRequest(handler, http.MethodGet, "/api/v1/users/me", "", accessToken)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/users/me status = %d, want %d, body=%s", getRec.Code, http.StatusOK, getRec.Body.String())
	}

	updateRec := performAuthedRequest(handler, http.MethodPut, "/api/v1/users/me", `{"full_name":"Updated Name"}`, accessToken)
	if updateRec.Code != http.StatusOK {
		t.Fatalf("PUT /api/v1/users/me status = %d, want %d, body=%s", updateRec.Code, http.StatusOK, updateRec.Body.String())
	}

	updatedUser, err := store.GetUserByID(ctx, org.ID, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID() error = %v", err)
	}
	if updatedUser.FullName == nil || *updatedUser.FullName != "Updated Name" {
		t.Fatalf("updated full name = %v, want %q", updatedUser.FullName, "Updated Name")
	}
}

func TestRouterAllowsGrantedPermissions(t *testing.T) {
	store := testutil.RequireTestStore(t)
	handler := newTestRouter(store)

	tests := []struct {
		name       string
		permission string
		method     string
		path       func(t *testing.T, ctx context.Context, store *db.Store, orgID uuid.UUID) string
		body       string
		wantStatus int
	}{
		{
			name:       "users read",
			permission: domain.PermissionUsersRead,
			method:     http.MethodGet,
			path:       func(_ *testing.T, _ context.Context, _ *db.Store, _ uuid.UUID) string { return "/api/v1/users" },
			wantStatus: http.StatusOK,
		},
		{
			name:       "users write",
			permission: domain.PermissionUsersWrite,
			method:     http.MethodPost,
			path: func(_ *testing.T, _ context.Context, _ *db.Store, _ uuid.UUID) string {
				return "/api/v1/users"
			},
			body:       `{"email":"create-` + uuid.NewString() + `@example.com","password":"S3cur3P@ss!"}`,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "users delete",
			permission: domain.PermissionUsersDelete,
			method:     http.MethodDelete,
			path: func(t *testing.T, _ context.Context, store *db.Store, orgID uuid.UUID) string {
				target := testutil.CreateUser(t, store, orgID, "router-delete-user")
				return "/api/v1/users/" + target.ID.String()
			},
			wantStatus: http.StatusOK,
		},
		{
			name:       "roles read",
			permission: domain.PermissionRolesRead,
			method:     http.MethodGet,
			path:       func(_ *testing.T, _ context.Context, _ *db.Store, _ uuid.UUID) string { return "/api/v1/roles" },
			wantStatus: http.StatusOK,
		},
		{
			name:       "roles write",
			permission: domain.PermissionRolesWrite,
			method:     http.MethodPost,
			path:       func(_ *testing.T, _ context.Context, _ *db.Store, _ uuid.UUID) string { return "/api/v1/roles" },
			body:       `{"name":"support"}`,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "roles delete",
			permission: domain.PermissionRolesDelete,
			method:     http.MethodDelete,
			path: func(t *testing.T, _ context.Context, store *db.Store, orgID uuid.UUID) string {
				role := testutil.CreateRole(t, store, orgID, "router-delete-role")
				return "/api/v1/roles/" + role.ID.String()
			},
			wantStatus: http.StatusOK,
		},
		{
			name:       "api keys read",
			permission: domain.PermissionAPIKeysRead,
			method:     http.MethodGet,
			path:       func(_ *testing.T, _ context.Context, _ *db.Store, _ uuid.UUID) string { return "/api/v1/api-keys" },
			wantStatus: http.StatusOK,
		},
		{
			name:       "api keys write",
			permission: domain.PermissionAPIKeysWrite,
			method:     http.MethodPost,
			path:       func(_ *testing.T, _ context.Context, _ *db.Store, _ uuid.UUID) string { return "/api/v1/api-keys" },
			body:       `{"name":"build-bot"}`,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "api keys delete",
			permission: domain.PermissionAPIKeysDelete,
			method:     http.MethodDelete,
			path: func(t *testing.T, ctx context.Context, store *db.Store, orgID uuid.UUID) string {
				key, err := store.CreateAPIKey(ctx, orgID, "router-delete-key", "uni", uuid.NewString(), []string{}, nil)
				if err != nil {
					t.Fatalf("CreateAPIKey() error = %v", err)
				}
				return "/api/v1/api-keys/" + key.ID.String()
			},
			wantStatus: http.StatusOK,
		},
		{
			name:       "audit read",
			permission: domain.PermissionAuditRead,
			method:     http.MethodGet,
			path:       func(_ *testing.T, _ context.Context, _ *db.Store, _ uuid.UUID) string { return "/api/v1/audit" },
			wantStatus: http.StatusOK,
		},
		{
			name:       "webhooks read",
			permission: domain.PermissionWebhooksRead,
			method:     http.MethodGet,
			path:       func(_ *testing.T, _ context.Context, _ *db.Store, _ uuid.UUID) string { return "/api/v1/webhooks" },
			wantStatus: http.StatusOK,
		},
		{
			name:       "webhooks write",
			permission: domain.PermissionWebhooksWrite,
			method:     http.MethodPost,
			path:       func(_ *testing.T, _ context.Context, _ *db.Store, _ uuid.UUID) string { return "/api/v1/webhooks" },
			body:       `{"url":"https://example.com/hooks","events":["user.login"]}`,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "webhooks delete",
			permission: domain.PermissionWebhooksDelete,
			method:     http.MethodDelete,
			path: func(t *testing.T, ctx context.Context, store *db.Store, orgID uuid.UUID) string {
				webhook, err := store.CreateWebhook(ctx, orgID, "https://example.com/delete-hook", []string{"user.login"}, "secret")
				if err != nil {
					t.Fatalf("CreateWebhook() error = %v", err)
				}
				return "/api/v1/webhooks/" + webhook.ID.String()
			},
			wantStatus: http.StatusOK,
		},
		{
			name:       "organizations read",
			permission: domain.PermissionOrganizationsRead,
			method:     http.MethodGet,
			path: func(_ *testing.T, _ context.Context, _ *db.Store, _ uuid.UUID) string {
				return "/api/v1/organizations/me"
			},
			wantStatus: http.StatusOK,
		},
		{
			name:       "organizations write",
			permission: domain.PermissionOrganizationsWrite,
			method:     http.MethodPut,
			path: func(_ *testing.T, _ context.Context, _ *db.Store, _ uuid.UUID) string {
				return "/api/v1/organizations/me"
			},
			body:       `{"name":"Renamed Org"}`,
			wantStatus: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			org := testutil.CreateOrganization(t, store, "router-allowed-org")
			user := testutil.CreateUser(t, store, org.ID, "router-allowed-user")
			grantPermissionToUser(t, ctx, store, org.ID, user.ID, tc.permission)

			path := tc.path(t, ctx, store, org.ID)
			rec := performAuthedRequest(handler, tc.method, path, tc.body, issueAccessToken(t, user.ID, org.ID))
			if rec.Code != tc.wantStatus {
				t.Fatalf("%s %s status = %d, want %d, body=%s", tc.method, path, rec.Code, tc.wantStatus, rec.Body.String())
			}
		})
	}
}

func TestRouterAllowsSuperuserBypass(t *testing.T) {
	store := testutil.RequireTestStore(t)
	handler := newTestRouter(store)

	tests := []struct {
		name       string
		method     string
		path       func(t *testing.T, ctx context.Context, store *db.Store, orgID uuid.UUID) string
		body       string
		wantStatus int
	}{
		{
			name:       "users family",
			method:     http.MethodGet,
			path:       func(_ *testing.T, _ context.Context, _ *db.Store, _ uuid.UUID) string { return "/api/v1/users" },
			wantStatus: http.StatusOK,
		},
		{
			name:   "create user",
			method: http.MethodPost,
			path:   func(_ *testing.T, _ context.Context, _ *db.Store, _ uuid.UUID) string { return "/api/v1/users" },
			body:   `{"email":"superuser-create-` + uuid.NewString() + `@example.com","password":"S3cur3P@ss!"}`,
			wantStatus: http.StatusCreated,
		},
		{
			name:   "organizations family",
			method: http.MethodGet,
			path: func(_ *testing.T, _ context.Context, _ *db.Store, _ uuid.UUID) string {
				return "/api/v1/organizations/me"
			},
			wantStatus: http.StatusOK,
		},
		{
			name:       "roles family",
			method:     http.MethodGet,
			path:       func(_ *testing.T, _ context.Context, _ *db.Store, _ uuid.UUID) string { return "/api/v1/roles" },
			wantStatus: http.StatusOK,
		},
		{
			name:       "api keys family",
			method:     http.MethodGet,
			path:       func(_ *testing.T, _ context.Context, _ *db.Store, _ uuid.UUID) string { return "/api/v1/api-keys" },
			wantStatus: http.StatusOK,
		},
		{
			name:       "audit family",
			method:     http.MethodGet,
			path:       func(_ *testing.T, _ context.Context, _ *db.Store, _ uuid.UUID) string { return "/api/v1/audit" },
			wantStatus: http.StatusOK,
		},
		{
			name:       "webhooks family",
			method:     http.MethodGet,
			path:       func(_ *testing.T, _ context.Context, _ *db.Store, _ uuid.UUID) string { return "/api/v1/webhooks" },
			wantStatus: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			org := testutil.CreateOrganization(t, store, "router-super-org")
			superuser := createSuperuser(t, ctx, store, org.ID, "router-super-user")

			path := tc.path(t, ctx, store, org.ID)
			rec := performAuthedRequest(handler, tc.method, path, tc.body, issueAccessToken(t, superuser.ID, org.ID))
			if rec.Code != tc.wantStatus {
				t.Fatalf("%s %s status = %d, want %d, body=%s", tc.method, path, rec.Code, tc.wantStatus, rec.Body.String())
			}
		})
	}
}

func newTestRouter(store *db.Store) http.Handler {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Environment: "development",
		},
		Auth: config.AuthConfig{
			JWTSecret:            routerTestJWTSecret,
			AccessTokenDuration:  15 * time.Minute,
			RefreshTokenDuration: 7 * 24 * time.Hour,
			RateLimitPerMinute:   1000,
		},
		Email: config.EmailConfig{
			BaseURL: "http://localhost:8080",
		},
	}

	return api.NewRouter(cfg, store, nil, testutil.DiscardLogger())
}

func issueAccessToken(t *testing.T, userID, orgID uuid.UUID) string {
	t.Helper()

	maker := token.NewMaker(routerTestJWTSecret, 15*time.Minute, 7*24*time.Hour)
	tokenStr, _, err := maker.CreateAccessToken(userID, orgID)
	if err != nil {
		t.Fatalf("CreateAccessToken() error = %v", err)
	}
	return tokenStr
}

func performAuthedRequest(handler http.Handler, method, path, body, accessToken string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+accessToken)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func createSuperuser(t *testing.T, ctx context.Context, store *db.Store, orgID uuid.UUID, prefix string) *domain.User {
	t.Helper()

	fullName := prefix + "-name"
	email := fmt.Sprintf("%s-%s@example.com", prefix, strings.ToLower(uuid.NewString()))
	user, err := store.CreateUser(ctx, orgID, email, "hashed-password", &fullName, true)
	if err != nil {
		t.Fatalf("CreateUser(superuser) error = %v", err)
	}
	return user
}

func grantPermissionToUser(t *testing.T, ctx context.Context, store *db.Store, orgID, userID uuid.UUID, permission string) {
	t.Helper()

	role := testutil.CreateRole(t, store, orgID, "router-permission-role")
	p, err := store.GetPermissionByName(ctx, permission)
	if err != nil {
		t.Fatalf("GetPermissionByName(%q) error = %v", permission, err)
	}
	if err := store.AssignPermissionToRole(ctx, role.ID, p.ID); err != nil {
		t.Fatalf("AssignPermissionToRole() error = %v", err)
	}
	if err := store.AssignRoleToUser(ctx, orgID, userID, role.ID); err != nil {
		t.Fatalf("AssignRoleToUser() error = %v", err)
	}
}
