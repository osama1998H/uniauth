package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/osama1998h/uniauth/internal/domain"
)

func (s *Store) CreateAuditLog(ctx context.Context, log *domain.AuditLog) error {
	var metaJSON []byte
	if log.Metadata != nil {
		var err error
		metaJSON, err = json.Marshal(log.Metadata)
		if err != nil {
			return fmt.Errorf("marshal metadata: %w", err)
		}
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO audit_logs (org_id, user_id, action, resource_type, resource_id, metadata, ip_address, user_agent)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		log.OrgID, log.UserID, log.Action, log.ResourceType, log.ResourceID, metaJSON, log.IPAddress, log.UserAgent,
	)
	return err
}

func (s *Store) ListAuditLogs(ctx context.Context, orgID uuid.UUID, filter domain.AuditFilter) ([]*domain.AuditLog, error) {
	limit := filter.Limit
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	// Build query with optional filters
	rows, err := s.pool.Query(ctx,
		`SELECT id, org_id, user_id, action, resource_type, resource_id, metadata, ip_address, user_agent, created_at
		 FROM audit_logs
		 WHERE org_id = $1
		   AND ($2::uuid IS NULL OR user_id = $2)
		   AND ($3::text IS NULL OR action = $3)
		   AND ($4::timestamptz IS NULL OR created_at >= $4)
		   AND ($5::timestamptz IS NULL OR created_at <= $5)
		 ORDER BY created_at DESC
		 LIMIT $6 OFFSET $7`,
		orgID, filter.UserID, filter.Action, timeOrNil(filter.Since), timeOrNil(filter.Until), limit, filter.Offset,
	)
	if err != nil {
		return nil, fmt.Errorf("list audit logs: %w", err)
	}
	defer rows.Close()

	var logs []*domain.AuditLog
	for rows.Next() {
		l := &domain.AuditLog{}
		var metaJSON []byte
		if err := rows.Scan(
			&l.ID, &l.OrgID, &l.UserID, &l.Action,
			&l.ResourceType, &l.ResourceID, &metaJSON,
			&l.IPAddress, &l.UserAgent, &l.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan audit log: %w", err)
		}
		if metaJSON != nil {
			_ = json.Unmarshal(metaJSON, &l.Metadata)
		}
		logs = append(logs, l)
	}
	return logs, rows.Err()
}

func timeOrNil(t *time.Time) interface{} {
	if t == nil {
		return nil
	}
	return *t
}
