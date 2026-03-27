-- name: CreatePasswordResetToken :one
INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetPasswordResetToken :one
SELECT * FROM password_reset_tokens
WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
LIMIT 1;

-- name: MarkPasswordResetTokenUsed :exec
UPDATE password_reset_tokens SET used_at = now() WHERE id = $1;

-- name: DeleteExpiredPasswordResetTokens :exec
DELETE FROM password_reset_tokens WHERE expires_at < now();
