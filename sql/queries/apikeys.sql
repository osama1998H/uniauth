-- name: CreateAPIKey :one
INSERT INTO api_keys (org_id, name, key_prefix, key_hash, scopes, expires_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetAPIKeyByHash :one
SELECT * FROM api_keys WHERE key_hash = $1 LIMIT 1;

-- name: ListAPIKeysByOrg :many
SELECT * FROM api_keys
WHERE org_id = $1 AND revoked_at IS NULL
ORDER BY created_at DESC;

-- name: RevokeAPIKey :exec
UPDATE api_keys SET revoked_at = now() WHERE id = $1 AND org_id = $2;

-- name: UpdateAPIKeyLastUsed :exec
UPDATE api_keys SET last_used_at = now() WHERE id = $1;
