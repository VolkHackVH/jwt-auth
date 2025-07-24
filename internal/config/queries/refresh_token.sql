-- name: CreateToken :one
INSERT INTO refresh_tokens (user_id, token_hash, user_agent, ip_address)
VALUES ($1, $2, $3, $4)
RETURNING id, user_id, user_agent;

-- name: FindRefreshTokenByUser :one
SELECT id, user_id, token_hash, user_agent, ip_address, created_at
FROM refresh_tokens
WHERE user_id = $1;

-- name: FindRefreshToken :one
SELECT id, user_id, token_hash, user_agent, ip_address, created_at
FROM refresh_tokens
WHERE user_id = $1 AND user_agent = $2;

-- name: UpdateToken :one
UPDATE refresh_tokens
SET token_hash = $2
WHERE id = $1
RETURNING id, user_id, user_agent;

-- name: DeleteToken :exec
DELETE FROM refresh_tokens
WHERE user_id = $1 AND user_agent = $2;
