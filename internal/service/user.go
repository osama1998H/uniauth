package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/osama1998h/uniauth/internal/domain"
	db "github.com/osama1998h/uniauth/internal/repository/postgres"
)

// UserService handles user management logic.
type UserService struct {
	store    *db.Store
	auditSvc *AuditService
}

// NewUserService creates a UserService.
func NewUserService(store *db.Store, auditSvc *AuditService) *UserService {
	return &UserService{store: store, auditSvc: auditSvc}
}

// GetByID returns a user by ID.
func (s *UserService) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	return s.store.GetUserByID(ctx, id)
}

// UpdateProfile updates the user's full name and/or email.
type UpdateProfileInput struct {
	FullName *string
	Email    *string
}

func (s *UserService) UpdateProfile(ctx context.Context, userID uuid.UUID, in UpdateProfileInput) (*domain.User, error) {
	user, err := s.store.UpdateUser(ctx, userID, in.FullName, in.Email)
	if err != nil {
		return nil, fmt.Errorf("update user: %w", err)
	}
	s.auditSvc.Log(&domain.AuditLog{
		OrgID:        &user.OrgID,
		UserID:       &userID,
		Action:       domain.AuditActionUserUpdated,
		ResourceType: strPtr("user"),
		ResourceID:   strPtr(userID.String()),
	})
	return user, nil
}

// ListByOrg returns paginated users for an organization.
func (s *UserService) ListByOrg(ctx context.Context, orgID uuid.UUID, limit, offset int) ([]*domain.User, error) {
	return s.store.ListUsersByOrg(ctx, orgID, limit, offset)
}

// Deactivate soft-deletes a user by marking them inactive.
func (s *UserService) Deactivate(ctx context.Context, actorID, targetUserID uuid.UUID) error {
	user, err := s.store.GetUserByID(ctx, targetUserID)
	if err != nil {
		return domain.ErrNotFound
	}
	if err := s.store.DeactivateUser(ctx, targetUserID); err != nil {
		return fmt.Errorf("deactivate user: %w", err)
	}
	s.auditSvc.Log(&domain.AuditLog{
		OrgID:        &user.OrgID,
		UserID:       &actorID,
		Action:       domain.AuditActionUserDeactivated,
		ResourceType: strPtr("user"),
		ResourceID:   strPtr(targetUserID.String()),
	})
	return nil
}

func strPtr(s string) *string { return &s }
