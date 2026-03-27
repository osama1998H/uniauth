package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/osama1998h/uniauth/internal/domain"
)

func (s *Store) CreateUser(ctx context.Context, orgID uuid.UUID, email, hashedPassword string, fullName *string, isSuperuser bool) (*domain.User, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO users (org_id, email, hashed_password, full_name, is_superuser)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, org_id, email, hashed_password, full_name, is_active, is_superuser, email_verified_at, last_login_at, created_at, updated_at`,
		orgID, email, hashedPassword, fullName, isSuperuser,
	)
	return scanUser(row)
}

func (s *Store) GetUserByID(ctx context.Context, orgID, id uuid.UUID) (*domain.User, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, org_id, email, hashed_password, full_name, is_active, is_superuser, email_verified_at, last_login_at, created_at, updated_at
		 FROM users WHERE org_id = $1 AND id = $2`, orgID, id,
	)
	u, err := scanUser(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	return u, err
}

func (s *Store) GetUserByEmail(ctx context.Context, orgID uuid.UUID, email string) (*domain.User, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, org_id, email, hashed_password, full_name, is_active, is_superuser, email_verified_at, last_login_at, created_at, updated_at
		 FROM users WHERE org_id = $1 AND email = $2`, orgID, email,
	)
	u, err := scanUser(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	return u, err
}

func (s *Store) ListUsersByOrg(ctx context.Context, orgID uuid.UUID, limit, offset int) ([]*domain.User, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, org_id, email, hashed_password, full_name, is_active, is_superuser, email_verified_at, last_login_at, created_at, updated_at
		 FROM users WHERE org_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
		orgID, limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()
	return collectUsers(rows)
}

func (s *Store) UpdateUser(ctx context.Context, orgID, id uuid.UUID, fullName, email *string) (*domain.User, error) {
	row := s.pool.QueryRow(ctx,
		`UPDATE users
		 SET full_name  = COALESCE($3, full_name),
		     email      = COALESCE($4, email),
		     updated_at = now()
		 WHERE org_id = $1 AND id = $2
		 RETURNING id, org_id, email, hashed_password, full_name, is_active, is_superuser, email_verified_at, last_login_at, created_at, updated_at`,
		orgID, id, fullName, email,
	)
	u, err := scanUser(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	return u, err
}

func (s *Store) UpdateUserPassword(ctx context.Context, id uuid.UUID, hashedPassword string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET hashed_password = $2, updated_at = now() WHERE id = $1`, id, hashedPassword,
	)
	return err
}

func (s *Store) UpdateUserLastLogin(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET last_login_at = now(), updated_at = now() WHERE id = $1`, id,
	)
	return err
}

func (s *Store) DeactivateUser(ctx context.Context, orgID, id uuid.UUID) error {
	var userID uuid.UUID
	err := s.pool.QueryRow(ctx,
		`UPDATE users
		 SET is_active = false, updated_at = now()
		 WHERE org_id = $1 AND id = $2
		 RETURNING id`,
		orgID, id,
	).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	return err
}

func scanUser(row pgx.Row) (*domain.User, error) {
	u := &domain.User{}
	err := row.Scan(
		&u.ID, &u.OrgID, &u.Email, &u.HashedPassword, &u.FullName,
		&u.IsActive, &u.IsSuperuser, &u.EmailVerifiedAt, &u.LastLoginAt,
		&u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("scan user: %w", err)
	}
	return u, nil
}

func collectUsers(rows pgx.Rows) ([]*domain.User, error) {
	var users []*domain.User
	for rows.Next() {
		u := &domain.User{}
		if err := rows.Scan(
			&u.ID, &u.OrgID, &u.Email, &u.HashedPassword, &u.FullName,
			&u.IsActive, &u.IsSuperuser, &u.EmailVerifiedAt, &u.LastLoginAt,
			&u.CreatedAt, &u.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan user row: %w", err)
		}
		users = append(users, u)
	}
	return users, rows.Err()
}
