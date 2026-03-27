-- name: CreateAuditLog :one
INSERT INTO audit_logs (org_id, user_id, action, resource_type, resource_id, metadata, ip_address, user_agent)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: ListAuditLogs :many
SELECT * FROM audit_logs
WHERE org_id = $1
  AND ($2::uuid IS NULL OR user_id = $2)
  AND ($3::text IS NULL OR action = $3)
  AND ($4::timestamptz IS NULL OR created_at >= $4)
  AND ($5::timestamptz IS NULL OR created_at <= $5)
ORDER BY created_at DESC
LIMIT $6 OFFSET $7;
