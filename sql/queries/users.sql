-- name: CreateUser :one
INSERT INTO users (org_id, email, hashed_password, full_name, is_superuser)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1 LIMIT 1;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE org_id = $1 AND email = $2 LIMIT 1;

-- name: GetUserByEmailAnyOrg :one
SELECT * FROM users WHERE email = $1 LIMIT 1;

-- name: ListUsersByOrg :many
SELECT * FROM users
WHERE org_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: UpdateUser :one
UPDATE users
SET full_name  = COALESCE($2, full_name),
    email      = COALESCE($3, email),
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: UpdateUserPassword :exec
UPDATE users SET hashed_password = $2, updated_at = now() WHERE id = $1;

-- name: UpdateUserLastLogin :exec
UPDATE users SET last_login_at = now(), updated_at = now() WHERE id = $1;

-- name: DeactivateUser :exec
UPDATE users SET is_active = false, updated_at = now() WHERE id = $1;

-- name: VerifyUserEmail :exec
UPDATE users SET email_verified_at = now(), updated_at = now() WHERE id = $1;
