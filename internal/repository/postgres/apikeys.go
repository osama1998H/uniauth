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

func (s *Store) CreateAPIKey(ctx context.Context, orgID uuid.UUID, name, keyPrefix, keyHash string, scopes []string, expiresAt *time.Time) (*domain.APIKey, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO api_keys (org_id, name, key_prefix, key_hash, scopes, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, org_id, name, key_prefix, key_hash, scopes, expires_at, last_used_at, revoked_at, created_at`,
		orgID, name, keyPrefix, keyHash, scopes, expiresAt,
	)
	return scanAPIKey(row)
}

func (s *Store) GetAPIKeyByHash(ctx context.Context, keyHash string) (*domain.APIKey, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, org_id, name, key_prefix, key_hash, scopes, expires_at, last_used_at, revoked_at, created_at
		 FROM api_keys WHERE key_hash = $1`, keyHash,
	)
	k, err := scanAPIKey(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	return k, err
}

func (s *Store) ListAPIKeysByOrg(ctx context.Context, orgID uuid.UUID) ([]*domain.APIKey, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, org_id, name, key_prefix, key_hash, scopes, expires_at, last_used_at, revoked_at, created_at
		 FROM api_keys WHERE org_id = $1 AND revoked_at IS NULL ORDER BY created_at DESC`, orgID,
	)
	if err != nil {
		return nil, fmt.Errorf("list api keys: %w", err)
	}
	defer rows.Close()

	var keys []*domain.APIKey
	for rows.Next() {
		k, err := scanAPIKeyRow(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

func (s *Store) RevokeAPIKey(ctx context.Context, id, orgID uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE api_keys SET revoked_at = now() WHERE id = $1 AND org_id = $2`, id, orgID,
	)
	return err
}

func (s *Store) UpdateAPIKeyLastUsed(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `UPDATE api_keys SET last_used_at = now() WHERE id = $1`, id)
	return err
}

func scanAPIKey(row pgx.Row) (*domain.APIKey, error) {
	k := &domain.APIKey{}
	if err := row.Scan(&k.ID, &k.OrgID, &k.Name, &k.KeyPrefix, &k.KeyHash, &k.Scopes, &k.ExpiresAt, &k.LastUsedAt, &k.RevokedAt, &k.CreatedAt); err != nil {
		return nil, fmt.Errorf("scan api key: %w", err)
	}
	return k, nil
}

func scanAPIKeyRow(rows pgx.Rows) (*domain.APIKey, error) {
	k := &domain.APIKey{}
	if err := rows.Scan(&k.ID, &k.OrgID, &k.Name, &k.KeyPrefix, &k.KeyHash, &k.Scopes, &k.ExpiresAt, &k.LastUsedAt, &k.RevokedAt, &k.CreatedAt); err != nil {
		return nil, fmt.Errorf("scan api key row: %w", err)
	}
	return k, nil
}
