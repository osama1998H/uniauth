package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/osama1998h/uniauth/internal/domain"
	db "github.com/osama1998h/uniauth/internal/repository/postgres"
	"github.com/osama1998h/uniauth/pkg/token"
)

// APIKeyService manages API keys.
type APIKeyService struct {
	store    *db.Store
	auditSvc *AuditService
}

// NewAPIKeyService creates an APIKeyService.
func NewAPIKeyService(store *db.Store, auditSvc *AuditService) *APIKeyService {
	return &APIKeyService{store: store, auditSvc: auditSvc}
}

// CreateAPIKeyInput holds parameters for creating an API key.
type CreateAPIKeyInput struct {
	OrgID     uuid.UUID
	Name      string
	Scopes    []string
	ExpiresAt *time.Time
}

// CreateAPIKeyOutput includes the plaintext key (shown once) and the stored key record.
type CreateAPIKeyOutput struct {
	PlaintextKey string
	APIKey       *domain.APIKey
}

// Create generates a new API key.
func (s *APIKeyService) Create(ctx context.Context, in CreateAPIKeyInput, actorID uuid.UUID) (*CreateAPIKeyOutput, error) {
	plaintext, prefix, err := token.GenerateAPIKey()
	if err != nil {
		return nil, fmt.Errorf("generate api key: %w", err)
	}

	keyHash := token.HashAPIKey(plaintext)

	key, err := s.store.CreateAPIKey(ctx, in.OrgID, in.Name, prefix, keyHash, in.Scopes, in.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("store api key: %w", err)
	}

	s.auditSvc.Log(&domain.AuditLog{
		OrgID: &in.OrgID, UserID: &actorID,
		Action: domain.AuditActionAPIKeyCreated,
		ResourceType: strPtr("api_key"), ResourceID: strPtr(key.ID.String()),
	})

	return &CreateAPIKeyOutput{PlaintextKey: plaintext, APIKey: key}, nil
}

// List returns all active API keys for an organization.
func (s *APIKeyService) List(ctx context.Context, orgID uuid.UUID) ([]*domain.APIKey, error) {
	return s.store.ListAPIKeysByOrg(ctx, orgID)
}

// Revoke deactivates an API key.
func (s *APIKeyService) Revoke(ctx context.Context, keyID, orgID, actorID uuid.UUID) error {
	if err := s.store.RevokeAPIKey(ctx, keyID, orgID); err != nil {
		return fmt.Errorf("revoke api key: %w", err)
	}
	s.auditSvc.Log(&domain.AuditLog{
		OrgID: &orgID, UserID: &actorID,
		Action: domain.AuditActionAPIKeyRevoked,
		ResourceType: strPtr("api_key"), ResourceID: strPtr(keyID.String()),
	})
	return nil
}

// ValidateAPIKey authenticates a raw API key and returns the associated org.
func (s *APIKeyService) ValidateAPIKey(ctx context.Context, plaintext string) (*domain.APIKey, error) {
	keyHash := token.HashAPIKey(plaintext)
	key, err := s.store.GetAPIKeyByHash(ctx, keyHash)
	if err != nil {
		return nil, domain.ErrUnauthorized
	}
	if !key.IsValid() {
		if key.RevokedAt != nil {
			return nil, domain.ErrAPIKeyRevoked
		}
		return nil, domain.ErrAPIKeyExpired
	}

	// Update last_used_at async
	go func() {
		_ = s.store.UpdateAPIKeyLastUsed(context.Background(), key.ID)
	}()

	return key, nil
}
