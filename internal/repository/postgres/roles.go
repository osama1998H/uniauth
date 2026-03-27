package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/osama1998h/uniauth/internal/domain"
)

func (s *Store) CreateRole(ctx context.Context, orgID uuid.UUID, name string, description *string) (*domain.Role, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO roles (org_id, name, description)
		 VALUES ($1, $2, $3)
		 RETURNING id, org_id, name, description, created_at`,
		orgID, name, description,
	)
	return scanRole(row)
}

func (s *Store) GetRoleByID(ctx context.Context, orgID, id uuid.UUID) (*domain.Role, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, org_id, name, description, created_at FROM roles WHERE org_id = $1 AND id = $2`, orgID, id,
	)
	r, err := scanRole(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	return r, err
}

func (s *Store) ListRolesByOrg(ctx context.Context, orgID uuid.UUID) ([]*domain.Role, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, org_id, name, description, created_at FROM roles WHERE org_id = $1 ORDER BY name`, orgID,
	)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	defer rows.Close()

	var roles []*domain.Role
	for rows.Next() {
		r := &domain.Role{}
		if err := rows.Scan(&r.ID, &r.OrgID, &r.Name, &r.Description, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}
		roles = append(roles, r)
	}
	return roles, rows.Err()
}

func (s *Store) UpdateRole(ctx context.Context, orgID, id uuid.UUID, name string, description *string) (*domain.Role, error) {
	row := s.pool.QueryRow(ctx,
		`UPDATE roles
		 SET name        = COALESCE($3, name),
		     description = COALESCE($4, description)
		 WHERE org_id = $1 AND id = $2
		 RETURNING id, org_id, name, description, created_at`,
		orgID, id, name, description,
	)
	r, err := scanRole(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	return r, err
}

func (s *Store) DeleteRole(ctx context.Context, orgID, id uuid.UUID) error {
	var roleID uuid.UUID
	err := s.pool.QueryRow(ctx,
		`DELETE FROM roles WHERE org_id = $1 AND id = $2 RETURNING id`,
		orgID, id,
	).Scan(&roleID)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	return err
}

func (s *Store) ListPermissions(ctx context.Context) ([]*domain.Permission, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, name, description FROM permissions ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list permissions: %w", err)
	}
	defer rows.Close()
	return collectPermissions(rows)
}

func (s *Store) AssignPermissionToRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		roleID, permissionID,
	)
	return err
}

func (s *Store) RemovePermissionFromRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = $2`, roleID, permissionID,
	)
	return err
}

func (s *Store) ListPermissionsByRole(ctx context.Context, roleID uuid.UUID) ([]*domain.Permission, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT p.id, p.name, p.description FROM permissions p
		 JOIN role_permissions rp ON rp.permission_id = p.id
		 WHERE rp.role_id = $1 ORDER BY p.name`, roleID,
	)
	if err != nil {
		return nil, fmt.Errorf("list permissions by role: %w", err)
	}
	defer rows.Close()
	return collectPermissions(rows)
}

func (s *Store) AssignRoleToUser(ctx context.Context, orgID, userID, roleID uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO user_roles (org_id, user_id, role_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
		orgID, userID, roleID,
	)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return domain.ErrNotFound
	}
	return err
}

func (s *Store) RemoveRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2`, userID, roleID,
	)
	return err
}

func (s *Store) ListRolesByUser(ctx context.Context, userID uuid.UUID) ([]*domain.Role, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT r.id, r.org_id, r.name, r.description, r.created_at FROM roles r
		 JOIN user_roles ur ON ur.role_id = r.id
		 WHERE ur.user_id = $1 ORDER BY r.name`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("list roles by user: %w", err)
	}
	defer rows.Close()

	var roles []*domain.Role
	for rows.Next() {
		r := &domain.Role{}
		if err := rows.Scan(&r.ID, &r.OrgID, &r.Name, &r.Description, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}
		roles = append(roles, r)
	}
	return roles, rows.Err()
}

func (s *Store) ListPermissionsByUser(ctx context.Context, userID uuid.UUID) ([]*domain.Permission, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT DISTINCT p.id, p.name, p.description FROM permissions p
		 JOIN role_permissions rp ON rp.permission_id = p.id
		 JOIN user_roles ur ON ur.role_id = rp.role_id
		 WHERE ur.user_id = $1 ORDER BY p.name`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("list permissions by user: %w", err)
	}
	defer rows.Close()
	return collectPermissions(rows)
}

func (s *Store) GetPermissionByName(ctx context.Context, name string) (*domain.Permission, error) {
	row := s.pool.QueryRow(ctx, `SELECT id, name, description FROM permissions WHERE name = $1`, name)
	p := &domain.Permission{}
	err := row.Scan(&p.ID, &p.Name, &p.Description)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get permission: %w", err)
	}
	return p, nil
}

func scanRole(row pgx.Row) (*domain.Role, error) {
	r := &domain.Role{}
	if err := row.Scan(&r.ID, &r.OrgID, &r.Name, &r.Description, &r.CreatedAt); err != nil {
		return nil, fmt.Errorf("scan role: %w", err)
	}
	return r, nil
}

func collectPermissions(rows pgx.Rows) ([]*domain.Permission, error) {
	var perms []*domain.Permission
	for rows.Next() {
		p := &domain.Permission{}
		if err := rows.Scan(&p.ID, &p.Name, &p.Description); err != nil {
			return nil, fmt.Errorf("scan permission: %w", err)
		}
		perms = append(perms, p)
	}
	return perms, rows.Err()
}
