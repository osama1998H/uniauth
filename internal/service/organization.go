package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/osama1998h/uniauth/internal/domain"
	db "github.com/osama1998h/uniauth/internal/repository/postgres"
)

// OrgService handles organization management logic.
type OrgService struct {
	store *db.Store
}

// NewOrgService creates an OrgService.
func NewOrgService(store *db.Store) *OrgService {
	return &OrgService{store: store}
}

// GetByID returns an organization by ID.
func (s *OrgService) GetByID(ctx context.Context, id uuid.UUID) (*domain.Organization, error) {
	return s.store.GetOrganizationByID(ctx, id)
}

// Update updates an organization's name.
func (s *OrgService) Update(ctx context.Context, id uuid.UUID, name string) (*domain.Organization, error) {
	org, err := s.store.UpdateOrganization(ctx, id, name)
	if err != nil {
		return nil, fmt.Errorf("update org: %w", err)
	}
	return org, nil
}
