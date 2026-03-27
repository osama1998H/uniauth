package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/osama1998h/uniauth/internal/domain"
)

func (s *Store) CreateOrganization(ctx context.Context, name, slug string) (*domain.Organization, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug)
		 VALUES ($1, $2)
		 RETURNING id, name, slug, is_active, created_at, updated_at`,
		name, slug,
	)
	return scanOrganization(row)
}

func (s *Store) GetOrganizationByID(ctx context.Context, id uuid.UUID) (*domain.Organization, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, name, slug, is_active, created_at, updated_at FROM organizations WHERE id = $1`, id,
	)
	org, err := scanOrganization(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	return org, err
}

func (s *Store) GetOrganizationBySlug(ctx context.Context, slug string) (*domain.Organization, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, name, slug, is_active, created_at, updated_at FROM organizations WHERE slug = $1`, slug,
	)
	org, err := scanOrganization(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	return org, err
}

func (s *Store) UpdateOrganization(ctx context.Context, id uuid.UUID, name string) (*domain.Organization, error) {
	row := s.pool.QueryRow(ctx,
		`UPDATE organizations SET name = $2, updated_at = now() WHERE id = $1
		 RETURNING id, name, slug, is_active, created_at, updated_at`,
		id, name,
	)
	org, err := scanOrganization(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	return org, err
}

func scanOrganization(row pgx.Row) (*domain.Organization, error) {
	o := &domain.Organization{}
	err := row.Scan(&o.ID, &o.Name, &o.Slug, &o.IsActive, &o.CreatedAt, &o.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("scan organization: %w", err)
	}
	return o, nil
}
