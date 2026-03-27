-- name: CreateRole :one
INSERT INTO roles (org_id, name, description)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetRoleByID :one
SELECT * FROM roles WHERE id = $1 LIMIT 1;

-- name: ListRolesByOrg :many
SELECT * FROM roles WHERE org_id = $1 ORDER BY name;

-- name: UpdateRole :one
UPDATE roles
SET name        = COALESCE($2, name),
    description = COALESCE($3, description)
WHERE id = $1
RETURNING *;

-- name: DeleteRole :exec
DELETE FROM roles WHERE id = $1;

-- name: ListPermissions :many
SELECT * FROM permissions ORDER BY name;

-- name: GetPermissionByName :one
SELECT * FROM permissions WHERE name = $1 LIMIT 1;

-- name: AssignPermissionToRole :exec
INSERT INTO role_permissions (role_id, permission_id)
VALUES ($1, $2)
ON CONFLICT DO NOTHING;

-- name: RemovePermissionFromRole :exec
DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = $2;

-- name: ListPermissionsByRole :many
SELECT p.* FROM permissions p
JOIN role_permissions rp ON rp.permission_id = p.id
WHERE rp.role_id = $1
ORDER BY p.name;

-- name: AssignRoleToUser :exec
INSERT INTO user_roles (user_id, role_id)
VALUES ($1, $2)
ON CONFLICT DO NOTHING;

-- name: RemoveRoleFromUser :exec
DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2;

-- name: ListRolesByUser :many
SELECT r.* FROM roles r
JOIN user_roles ur ON ur.role_id = r.id
WHERE ur.user_id = $1
ORDER BY r.name;

-- name: ListPermissionsByUser :many
SELECT DISTINCT p.* FROM permissions p
JOIN role_permissions rp ON rp.permission_id = p.id
JOIN user_roles ur ON ur.role_id = rp.role_id
WHERE ur.user_id = $1
ORDER BY p.name;
