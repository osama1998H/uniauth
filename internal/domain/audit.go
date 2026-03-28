package domain

import (
	"time"

	"github.com/google/uuid"
)

// Well-known audit action constants.
const (
	AuditActionUserCreated       = "user.created"
	AuditActionUserRegistered    = "user.registered"
	AuditActionUserLogin         = "user.login"
	AuditActionUserLoginFailed   = "user.login_failed"
	AuditActionUserLogout        = "user.logout"
	AuditActionUserUpdated       = "user.updated"
	AuditActionUserDeactivated   = "user.deactivated"
	AuditActionPasswordChanged   = "user.password_changed"
	AuditActionPasswordReset     = "user.password_reset"
	AuditActionTokenRefreshed    = "user.token_refreshed"
	AuditActionAPIKeyCreated     = "apikey.created"
	AuditActionAPIKeyRevoked     = "apikey.revoked"
	AuditActionRoleCreated       = "role.created"
	AuditActionRoleDeleted       = "role.deleted"
	AuditActionRoleAssigned      = "role.assigned"
)

type AuditLog struct {
	ID           uuid.UUID
	OrgID        *uuid.UUID
	UserID       *uuid.UUID
	Action       string
	ResourceType *string
	ResourceID   *string
	Metadata     map[string]any
	IPAddress    *string
	UserAgent    *string
	CreatedAt    time.Time
}

type AuditFilter struct {
	UserID *uuid.UUID
	Action *string
	Since  *time.Time
	Until  *time.Time
	Limit  int
	Offset int
}
