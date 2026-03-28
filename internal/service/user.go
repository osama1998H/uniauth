package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/bcrypt"

	"github.com/osama1998h/uniauth/internal/domain"
	db "github.com/osama1998h/uniauth/internal/repository/postgres"
)

// UserService handles user management logic.
type UserService struct {
	store      *db.Store
	auditSvc   *AuditService
	webhookSvc *WebhookService
}

// NewUserService creates a UserService.
func NewUserService(store *db.Store, auditSvc *AuditService, webhookSvc *WebhookService) *UserService {
	return &UserService{store: store, auditSvc: auditSvc, webhookSvc: webhookSvc}
}

// CreateUserInput holds the data required to create a user in an organization.
type CreateUserInput struct {
	Email    string
	Password string
	FullName *string
	RoleIDs  []uuid.UUID
}

// Create creates a new user inside the given organization.
// The new user always defaults to non-superuser.
func (s *UserService) Create(ctx context.Context, orgID, actorID uuid.UUID, in CreateUserInput, ipAddress, userAgent *string) (*domain.User, error) {
	if in.Email == "" {
		return nil, fmt.Errorf("%w: email is required", domain.ErrInvalidInput)
	}

	if err := ValidatePassword(in.Password); err != nil {
		return nil, err
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	user, err := s.store.CreateUser(ctx, orgID, in.Email, string(hashed), in.FullName, false)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, fmt.Errorf("%w: email already exists in this organization", domain.ErrAlreadyExists)
		}
		return nil, fmt.Errorf("create user: %w", err)
	}

	for _, roleID := range in.RoleIDs {
		if _, err := s.store.GetRoleByID(ctx, orgID, roleID); err != nil {
			return nil, fmt.Errorf("%w: role %s not found in organization", domain.ErrInvalidInput, roleID)
		}
		if err := s.store.AssignRoleToUser(ctx, orgID, user.ID, roleID); err != nil {
			return nil, fmt.Errorf("assign role %s: %w", roleID, err)
		}
	}

	s.auditSvc.Log(&domain.AuditLog{
		OrgID:        &orgID,
		UserID:       &actorID,
		Action:       domain.AuditActionUserCreated,
		ResourceType: strPtr("user"),
		ResourceID:   strPtr(user.ID.String()),
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
	})
	s.webhookSvc.Dispatch(orgID, domain.AuditActionUserCreated, map[string]any{
		"user_id": user.ID,
		"email":   user.Email,
	})

	return user, nil
}

// GetByID returns a user by ID within the caller's organization.
func (s *UserService) GetByID(ctx context.Context, orgID, id uuid.UUID) (*domain.User, error) {
	return s.store.GetUserByID(ctx, orgID, id)
}

// UpdateProfile updates the user's full name and/or email.
type UpdateProfileInput struct {
	FullName *string
	Email    *string
}

func (s *UserService) UpdateProfile(ctx context.Context, orgID, userID uuid.UUID, in UpdateProfileInput) (*domain.User, error) {
	user, err := s.store.UpdateUser(ctx, orgID, userID, in.FullName, in.Email)
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
func (s *UserService) Deactivate(ctx context.Context, orgID, actorID, targetUserID uuid.UUID) error {
	user, err := s.store.GetUserByID(ctx, orgID, targetUserID)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	if err := s.store.DeactivateUser(ctx, orgID, targetUserID); err != nil {
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
