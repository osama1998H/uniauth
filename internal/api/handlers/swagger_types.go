package handlers

// swagger_types.go — named types used only for Swagger schema generation.
// Handlers continue to use anonymous structs internally; these types mirror
// the JSON shapes that handlers actually produce.

// SwaggerErrorResponse is the standard error envelope returned on failures.
type SwaggerErrorResponse struct {
	Error string `json:"error" example:"something went wrong"`
}

// SwaggerMessageResponse is the standard success message envelope.
type SwaggerMessageResponse struct {
	Message string `json:"message" example:"operation completed successfully"`
}

// ---- View types (mirrors views.go output) ----

// UserView is the JSON representation of a user resource.
type UserView struct {
	ID              string  `json:"id"                example:"550e8400-e29b-41d4-a716-446655440000"`
	OrgID           string  `json:"org_id"            example:"550e8400-e29b-41d4-a716-446655440001"`
	Email           string  `json:"email"             example:"admin@acme.com"`
	FullName        *string `json:"full_name"         example:"Jane Doe"`
	IsActive        bool    `json:"is_active"         example:"true"`
	IsSuperuser     bool    `json:"is_superuser"      example:"false"`
	EmailVerifiedAt *string `json:"email_verified_at" example:"2026-01-01T00:00:00Z"`
	LastLoginAt     *string `json:"last_login_at"     example:"2026-03-01T12:00:00Z"`
	CreatedAt       string  `json:"created_at"        example:"2026-01-01T00:00:00Z"`
	UpdatedAt       string  `json:"updated_at"        example:"2026-03-01T12:00:00Z"`
}

// OrgView is the JSON representation of an organization resource.
type OrgView struct {
	ID        string `json:"id"         example:"550e8400-e29b-41d4-a716-446655440001"`
	Name      string `json:"name"       example:"Acme Corp"`
	Slug      string `json:"slug"       example:"acme-corp"`
	IsActive  bool   `json:"is_active"  example:"true"`
	CreatedAt string `json:"created_at" example:"2026-01-01T00:00:00Z"`
	UpdatedAt string `json:"updated_at" example:"2026-03-01T12:00:00Z"`
}

// RoleView is the JSON representation of a role resource.
type RoleView struct {
	ID          string  `json:"id"          example:"550e8400-e29b-41d4-a716-446655440002"`
	OrgID       string  `json:"org_id"      example:"550e8400-e29b-41d4-a716-446655440001"`
	Name        string  `json:"name"        example:"editor"`
	Description *string `json:"description" example:"Can edit content"`
	CreatedAt   string  `json:"created_at"  example:"2026-01-01T00:00:00Z"`
}

// PermissionView is the JSON representation of a permission resource.
type PermissionView struct {
	ID          string  `json:"id"          example:"550e8400-e29b-41d4-a716-446655440010"`
	Name        string  `json:"name"        example:"users:read"`
	Description *string `json:"description" example:"Read user profiles"`
}

// APIKeyView is the JSON representation of an API key resource (no secret).
type APIKeyView struct {
	ID         string   `json:"id"           example:"550e8400-e29b-41d4-a716-446655440003"`
	OrgID      string   `json:"org_id"       example:"550e8400-e29b-41d4-a716-446655440001"`
	Name       string   `json:"name"         example:"CI Deploy Key"`
	KeyPrefix  string   `json:"key_prefix"   example:"uk_live_"`
	Scopes     []string `json:"scopes"       example:"read:audit,write:webhooks"`
	ExpiresAt  *string  `json:"expires_at"   example:"2027-01-01T00:00:00Z"`
	LastUsedAt *string  `json:"last_used_at" example:"2026-03-15T08:00:00Z"`
	CreatedAt  string   `json:"created_at"   example:"2026-01-01T00:00:00Z"`
}

// AuditLogView is the JSON representation of an audit log entry.
type AuditLogView struct {
	ID           string         `json:"id"            example:"550e8400-e29b-41d4-a716-446655440020"`
	OrgID        *string        `json:"org_id"        example:"550e8400-e29b-41d4-a716-446655440001"`
	UserID       *string        `json:"user_id"       example:"550e8400-e29b-41d4-a716-446655440000"`
	Action       string         `json:"action"        example:"user.login"`
	ResourceType *string        `json:"resource_type" example:"user"`
	ResourceID   *string        `json:"resource_id"   example:"550e8400-e29b-41d4-a716-446655440000"`
	Metadata     map[string]any `json:"metadata"`
	IPAddress    *string        `json:"ip_address"    example:"192.168.1.1"`
	UserAgent    *string        `json:"user_agent"    example:"Mozilla/5.0"`
	CreatedAt    string         `json:"created_at"    example:"2026-03-01T12:00:00Z"`
}

// WebhookView is the JSON representation of a webhook resource.
type WebhookView struct {
	ID        string   `json:"id"         example:"550e8400-e29b-41d4-a716-446655440030"`
	OrgID     string   `json:"org_id"     example:"550e8400-e29b-41d4-a716-446655440001"`
	URL       string   `json:"url"        example:"https://app.example.com/hooks"`
	Events    []string `json:"events"     example:"user.created,user.deleted"`
	IsActive  bool     `json:"is_active"  example:"true"`
	CreatedAt string   `json:"created_at" example:"2026-01-01T00:00:00Z"`
}

// ---- Request types ----

// RegisterRequest is the request body for POST /api/v1/auth/register.
type RegisterRequest struct {
	OrgName  string  `json:"org_name"  example:"Acme Corp"`
	Email    string  `json:"email"     example:"admin@acme.com"`
	Password string  `json:"password"  example:"S3cur3P@ss!"`
	FullName *string `json:"full_name" example:"Jane Doe"`
}

// LoginRequest is the request body for POST /api/v1/auth/login.
type LoginRequest struct {
	OrgSlug  string `json:"org_slug" example:"acme-corp"`
	Email    string `json:"email"    example:"admin@acme.com"`
	Password string `json:"password" example:"S3cur3P@ss!"`
}

// RefreshRequest is the request body for POST /api/v1/auth/refresh.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" example:"eyJhbGci..."`
}

// LogoutRequest is the request body for POST /api/v1/auth/logout.
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" example:"eyJhbGci..."`
}

// ResetRequestBody is the request body for POST /api/v1/auth/password/reset-request.
type ResetRequestBody struct {
	OrgSlug string `json:"org_slug" example:"acme-corp"`
	Email   string `json:"email"    example:"admin@acme.com"`
}

// ResetConfirmBody is the request body for POST /api/v1/auth/password/reset-confirm.
type ResetConfirmBody struct {
	Token    string `json:"token"    example:"reset-token-abc123"`
	Password string `json:"password" example:"N3wS3cur3P@ss!"`
}

// ChangePasswordBody is the request body for PUT /api/v1/auth/password/change.
type ChangePasswordBody struct {
	CurrentPassword string `json:"current_password" example:"OldP@ss!1"`
	NewPassword     string `json:"new_password"     example:"N3wP@ss!1"`
}

// UpdateMeRequest is the request body for PUT /api/v1/users/me.
type UpdateMeRequest struct {
	FullName *string `json:"full_name" example:"Jane Smith"`
	Email    *string `json:"email"     example:"jane@acme.com"`
}

// CreateUserRequest is the request body for POST /api/v1/users.
type CreateUserRequest struct {
	Email    string   `json:"email"     example:"employee@acme.com"`
	Password string   `json:"password"  example:"S3cur3P@ss!"`
	FullName *string  `json:"full_name" example:"John Doe"`
	RoleIDs  []string `json:"role_ids"  example:"550e8400-e29b-41d4-a716-446655440002"`
}

// UpdateOrgRequest is the request body for PUT /api/v1/organizations/me.
type UpdateOrgRequest struct {
	Name string `json:"name" example:"Acme Corporation"`
}

// CreateRoleRequest is the request body for POST /api/v1/roles.
type CreateRoleRequest struct {
	Name        string  `json:"name"        example:"editor"`
	Description *string `json:"description" example:"Can edit content"`
}

// UpdateRoleRequest is the request body for PUT /api/v1/roles/{id}.
type UpdateRoleRequest struct {
	Name        string  `json:"name"        example:"editor"`
	Description *string `json:"description" example:"Can edit content"`
}

// AssignPermissionsRequest is the request body for POST /api/v1/roles/{id}/permissions.
type AssignPermissionsRequest struct {
	Permissions []string `json:"permissions" example:"users:read,users:write"`
}

// AssignRoleRequest is the request body for POST /api/v1/users/{id}/roles.
type AssignRoleRequest struct {
	RoleID string `json:"role_id" example:"550e8400-e29b-41d4-a716-446655440002"`
}

// CreateAPIKeyRequest is the request body for POST /api/v1/api-keys.
type CreateAPIKeyRequest struct {
	Name      string   `json:"name"       example:"CI Deploy Key"`
	Scopes    []string `json:"scopes"     example:"read:audit,write:webhooks"`
	ExpiresAt *string  `json:"expires_at" example:"2027-01-01T00:00:00Z"`
}

// CreateWebhookRequest is the request body for POST /api/v1/webhooks.
// URL must be a direct public HTTPS endpoint.
type CreateWebhookRequest struct {
	URL    string   `json:"url"    example:"https://app.example.com/hooks"`
	Events []string `json:"events" example:"user.created,user.deleted"`
}

// UpdateWebhookRequest is the request body for PUT /api/v1/webhooks/{id}.
// If URL is provided, it must be a direct public HTTPS endpoint.
type UpdateWebhookRequest struct {
	URL      *string  `json:"url"       example:"https://app.example.com/hooks/v2"`
	Events   []string `json:"events"    example:"user.created"`
	IsActive *bool    `json:"is_active" example:"true"`
}

// ---- Response types ----

// RegisterResponse is the response body for POST /api/v1/auth/register.
type RegisterResponse struct {
	Organization OrgView  `json:"organization"`
	User         UserView `json:"user"`
}

// TokenPairResponse is the response body for login and refresh endpoints.
type TokenPairResponse struct {
	AccessToken           string   `json:"access_token"             example:"eyJhbGci..."`
	RefreshToken          string   `json:"refresh_token"            example:"eyJhbGci..."`
	AccessTokenExpiresAt  string   `json:"access_token_expires_at"  example:"2026-03-27T16:00:00Z"`
	RefreshTokenExpiresAt string   `json:"refresh_token_expires_at" example:"2026-04-03T15:00:00Z"`
	User                  UserView `json:"user,omitempty"`
}

// UserListResponse is the response body for GET /api/v1/users.
type UserListResponse struct {
	Users  []UserView `json:"users"`
	Limit  int        `json:"limit"  example:"50"`
	Offset int        `json:"offset" example:"0"`
}

// PermissionsListResponse is the response body for GET /api/v1/roles/permissions.
type PermissionsListResponse struct {
	Permissions []PermissionView `json:"permissions"`
}

// RolesListResponse is the response body for GET /api/v1/roles.
type RolesListResponse struct {
	Roles []RoleView `json:"roles"`
}

// APIKeyListResponse is the response body for GET /api/v1/api-keys.
type APIKeyListResponse struct {
	APIKeys []APIKeyView `json:"api_keys"`
}

// CreateAPIKeyResponse is the response body for POST /api/v1/api-keys.
// The plaintext key is shown only once at creation time.
type CreateAPIKeyResponse struct {
	APIKeyView
	Key string `json:"key" example:"uk_live_abc123xyz456"`
}

// AuditListResponse is the response body for GET /api/v1/audit.
type AuditListResponse struct {
	Logs  []AuditLogView `json:"logs"`
	Count int            `json:"count" example:"42"`
}

// WebhookListResponse is the response body for GET /api/v1/webhooks.
type WebhookListResponse struct {
	Webhooks []WebhookView `json:"webhooks"`
}

// CreateWebhookResponse is the response body for POST /api/v1/webhooks.
// The HMAC secret is shown only once at creation time.
type CreateWebhookResponse struct {
	WebhookView
	Secret string `json:"secret" example:"whsec_abc123xyz456"`
}

// HealthReadyResponse is the response body for GET /ready.
type HealthReadyResponse struct {
	Status map[string]string `json:"status"`
}
