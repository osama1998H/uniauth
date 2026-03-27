-- name: CreateWebhook :one
INSERT INTO webhooks (org_id, url, events, secret)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetWebhookByID :one
SELECT * FROM webhooks WHERE id = $1 LIMIT 1;

-- name: ListWebhooksByOrg :many
SELECT * FROM webhooks WHERE org_id = $1 ORDER BY created_at DESC;

-- name: ListActiveWebhooksByOrgAndEvent :many
SELECT * FROM webhooks
WHERE org_id = $1
  AND is_active = true
  AND events @> ARRAY[$2]::text[];

-- name: UpdateWebhook :one
UPDATE webhooks
SET url       = COALESCE($2, url),
    events    = COALESCE($3, events),
    is_active = COALESCE($4, is_active)
WHERE id = $1 AND org_id = $5
RETURNING *;

-- name: DeleteWebhook :exec
DELETE FROM webhooks WHERE id = $1 AND org_id = $2;
