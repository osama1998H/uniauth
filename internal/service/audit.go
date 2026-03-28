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
	queue  *asyncDispatcher[*domain.AuditLog]
}

// NewAuditService creates an AuditService.
func NewAuditService(store *db.Store, logger *slog.Logger) *AuditService {
	svc := &AuditService{store: store, logger: logger}
	svc.queue = newAsyncDispatcher("audit_logs", logger, 1024, 2, func(log *domain.AuditLog) {
		if svc.store == nil {
			return
		}
		if err := svc.store.CreateAuditLog(context.Background(), log); err != nil && svc.logger != nil {
			svc.logger.Error("failed to write audit log", "error", err, "action", log.Action)
		}
	})
	return svc
}

// Log writes an audit entry through a bounded background worker so it never blocks the request.
func (a *AuditService) Log(log *domain.AuditLog) {
	if log == nil {
		return
	}
	a.queue.Enqueue(log)
}

// List returns paginated audit logs for an organization.
func (a *AuditService) List(ctx context.Context, orgID uuid.UUID, filter domain.AuditFilter) ([]*domain.AuditLog, error) {
	return a.store.ListAuditLogs(ctx, orgID, filter)
}
