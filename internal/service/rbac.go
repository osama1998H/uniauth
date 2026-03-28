package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/osama1998h/uniauth/internal/domain"
	db "github.com/osama1998h/uniauth/internal/repository/postgres"
)

// RBACService manages roles and permissions.
type RBACService struct {
	store    *db.Store
	auditSvc *AuditService
}

// NewRBACService creates a RBACService.
func NewRBACService(store *db.Store, auditSvc *AuditService) *RBACService {
	return &RBACService{store: store, auditSvc: auditSvc}
}

func (s *RBACService) CreateRole(ctx context.Context, orgID uuid.UUID, name string, description *string, actorID uuid.UUID) (*domain.Role, error) {
	role, err := s.store.CreateRole(ctx, orgID, name, description)
	if err != nil {
		return nil, fmt.Errorf("create role: %w", err)
	}
	s.auditSvc.Log(&domain.AuditLog{
		OrgID: &orgID, UserID: &actorID,
		Action:       domain.AuditActionRoleCreated,
		ResourceType: strPtr("role"), ResourceID: strPtr(role.ID.String()),
	})
	return role, nil
}

func (s *RBACService) GetRole(ctx context.Context, orgID, id uuid.UUID) (*domain.Role, error) {
	return s.store.GetRoleByID(ctx, orgID, id)
}

func (s *RBACService) ListRoles(ctx context.Context, orgID uuid.UUID) ([]*domain.Role, error) {
	return s.store.ListRolesByOrg(ctx, orgID)
}

func (s *RBACService) UpdateRole(ctx context.Context, orgID, id uuid.UUID, name string, description *string) (*domain.Role, error) {
	return s.store.UpdateRole(ctx, orgID, id, name, description)
}

func (s *RBACService) DeleteRole(ctx context.Context, orgID, id, actorID uuid.UUID) error {
	if err := s.store.DeleteRole(ctx, orgID, id); err != nil {
		return fmt.Errorf("delete role: %w", err)
	}
	s.auditSvc.Log(&domain.AuditLog{
		OrgID: &orgID, UserID: &actorID,
		Action:       domain.AuditActionRoleDeleted,
		ResourceType: strPtr("role"), ResourceID: strPtr(id.String()),
	})
	return nil
}

func (s *RBACService) ListPermissions(ctx context.Context) ([]*domain.Permission, error) {
	return s.store.ListPermissions(ctx)
}

func (s *RBACService) AssignPermissions(ctx context.Context, orgID, roleID uuid.UUID, permissionNames []string) error {
	if _, err := s.store.GetRoleByID(ctx, orgID, roleID); err != nil {
		return fmt.Errorf("get role: %w", err)
	}
	for _, name := range permissionNames {
		p, err := s.store.GetPermissionByName(ctx, name)
		if err != nil {
			return fmt.Errorf("permission '%s' not found", name)
		}
		if err := s.store.AssignPermissionToRole(ctx, roleID, p.ID); err != nil {
			return fmt.Errorf("assign permission: %w", err)
		}
	}
	return nil
}

func (s *RBACService) AssignRoleToUser(ctx context.Context, orgID, userID, roleID, actorID uuid.UUID) error {
	if _, err := s.store.GetUserByID(ctx, orgID, userID); err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	if _, err := s.store.GetRoleByID(ctx, orgID, roleID); err != nil {
		return fmt.Errorf("get role: %w", err)
	}
	if err := s.store.AssignRoleToUser(ctx, orgID, userID, roleID); err != nil {
		return fmt.Errorf("assign role: %w", err)
	}
	s.auditSvc.Log(&domain.AuditLog{
		OrgID: &orgID, UserID: &actorID,
		Action:       domain.AuditActionRoleAssigned,
		ResourceType: strPtr("user"), ResourceID: strPtr(userID.String()),
		Metadata: map[string]any{"role_id": roleID},
	})
	return nil
}

func (s *RBACService) RemoveRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error {
	return s.store.RemoveRoleFromUser(ctx, userID, roleID)
}

func (s *RBACService) ListUserRoles(ctx context.Context, userID uuid.UUID) ([]*domain.Role, error) {
	return s.store.ListRolesByUser(ctx, userID)
}

func (s *RBACService) ListUserPermissions(ctx context.Context, userID uuid.UUID) ([]*domain.Permission, error) {
	return s.store.ListPermissionsByUser(ctx, userID)
}

// HasPermission checks if a user has a specific permission within an organization.
func (s *RBACService) HasPermission(ctx context.Context, orgID, userID uuid.UUID, permission string) (bool, error) {
	return s.store.UserHasPermission(ctx, orgID, userID, permission)
}

// Authorize verifies that a user is allowed to perform an action in an organization.
func (s *RBACService) Authorize(ctx context.Context, orgID, userID uuid.UUID, permission string) error {
	userExists, allowed, err := s.store.AuthorizeUser(ctx, orgID, userID, permission)
	if err != nil {
		return fmt.Errorf("authorize actor: %w", err)
	}
	if !userExists {
		return domain.ErrUnauthorized
	}
	if !allowed {
		return domain.ErrForbidden
	}
	return nil
}
