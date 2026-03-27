package domain

import (
	"time"

	"github.com/google/uuid"
)

type Role struct {
	ID          uuid.UUID
	OrgID       uuid.UUID
	Name        string
	Description *string
	Permissions []Permission
	CreatedAt   time.Time
}

type Permission struct {
	ID          uuid.UUID
	Name        string // e.g. "users:read", "users:write"
	Description *string
}

const (
	PermissionUsersRead          = "users:read"
	PermissionUsersWrite         = "users:write"
	PermissionUsersDelete        = "users:delete"
	PermissionRolesRead          = "roles:read"
	PermissionRolesWrite         = "roles:write"
	PermissionRolesDelete        = "roles:delete"
	PermissionAPIKeysRead        = "apikeys:read"
	PermissionAPIKeysWrite       = "apikeys:write"
	PermissionAPIKeysDelete      = "apikeys:delete"
	PermissionAuditRead          = "audit:read"
	PermissionWebhooksRead       = "webhooks:read"
	PermissionWebhooksWrite      = "webhooks:write"
	PermissionWebhooksDelete     = "webhooks:delete"
	PermissionOrganizationsRead  = "organizations:read"
	PermissionOrganizationsWrite = "organizations:write"
)
