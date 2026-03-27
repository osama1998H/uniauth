package service

import (
	"context"
	"log/slog"

	"github.com/google/uuid"

	"github.com/osama1998h/uniauth/internal/domain"
	db "github.com/osama1998h/uniauth/internal/repository/postgres"
)

// AuditService writes audit log entries asynchronously.
type AuditService struct {
	store  *db.Store
	logger *slog.Logger
}

// NewAuditService creates an AuditService.
func NewAuditService(store *db.Store, logger *slog.Logger) *AuditService {
	return &AuditService{store: store, logger: logger}
}

// Log writes an audit entry in a fire-and-forget goroutine so it never blocks the request.
func (a *AuditService) Log(log *domain.AuditLog) {
	go func() {
		if err := a.store.CreateAuditLog(context.Background(), log); err != nil {
			a.logger.Error("failed to write audit log", "error", err, "action", log.Action)
		}
	}()
}

// List returns paginated audit logs for an organization.
func (a *AuditService) List(ctx context.Context, orgID uuid.UUID, filter domain.AuditFilter) ([]*domain.AuditLog, error) {
	return a.store.ListAuditLogs(ctx, orgID, filter)
}
