package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/osama1998h/uniauth/internal/domain"
)

type Webhook struct {
	ID        uuid.UUID
	OrgID     uuid.UUID
	URL       string
	Events    []string
	Secret    string
	IsActive  bool
	CreatedAt time.Time
}

func (s *Store) CreateWebhook(ctx context.Context, orgID uuid.UUID, url string, events []string, secret string) (*Webhook, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO webhooks (org_id, url, events, secret)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, org_id, url, events, secret, is_active, created_at`,
		orgID, url, events, secret,
	)
	return scanWebhook(row)
}

func (s *Store) GetWebhookByID(ctx context.Context, id uuid.UUID) (*Webhook, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, org_id, url, events, secret, is_active, created_at FROM webhooks WHERE id = $1`, id,
	)
	w, err := scanWebhook(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	return w, err
}

func (s *Store) ListWebhooksByOrg(ctx context.Context, orgID uuid.UUID) ([]*Webhook, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, org_id, url, events, secret, is_active, created_at FROM webhooks WHERE org_id = $1 ORDER BY created_at DESC`, orgID,
	)
	if err != nil {
		return nil, fmt.Errorf("list webhooks: %w", err)
	}
	defer rows.Close()

	var webhooks []*Webhook
	for rows.Next() {
		w := &Webhook{}
		if err := rows.Scan(&w.ID, &w.OrgID, &w.URL, &w.Events, &w.Secret, &w.IsActive, &w.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan webhook: %w", err)
		}
		webhooks = append(webhooks, w)
	}
	return webhooks, rows.Err()
}

func (s *Store) ListActiveWebhooksForEvent(ctx context.Context, orgID uuid.UUID, event string) ([]*Webhook, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, org_id, url, events, secret, is_active, created_at FROM webhooks
		 WHERE org_id = $1 AND is_active = true AND events @> ARRAY[$2]::text[]`,
		orgID, event,
	)
	if err != nil {
		return nil, fmt.Errorf("list active webhooks: %w", err)
	}
	defer rows.Close()

	var webhooks []*Webhook
	for rows.Next() {
		w := &Webhook{}
		if err := rows.Scan(&w.ID, &w.OrgID, &w.URL, &w.Events, &w.Secret, &w.IsActive, &w.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan webhook: %w", err)
		}
		webhooks = append(webhooks, w)
	}
	return webhooks, rows.Err()
}

func (s *Store) UpdateWebhook(ctx context.Context, id, orgID uuid.UUID, url *string, events []string, isActive *bool) (*Webhook, error) {
	row := s.pool.QueryRow(ctx,
		`UPDATE webhooks
		 SET url       = COALESCE($3, url),
		     events    = COALESCE($4, events),
		     is_active = COALESCE($5, is_active)
		 WHERE id = $1 AND org_id = $2
		 RETURNING id, org_id, url, events, secret, is_active, created_at`,
		id, orgID, url, events, isActive,
	)
	w, err := scanWebhook(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	return w, err
}

func (s *Store) DeleteWebhook(ctx context.Context, id, orgID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM webhooks WHERE id = $1 AND org_id = $2`, id, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func scanWebhook(row pgx.Row) (*Webhook, error) {
	w := &Webhook{}
	if err := row.Scan(&w.ID, &w.OrgID, &w.URL, &w.Events, &w.Secret, &w.IsActive, &w.CreatedAt); err != nil {
		return nil, fmt.Errorf("scan webhook: %w", err)
	}
	return w, nil
}
