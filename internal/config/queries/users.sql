-- name: CreateUser :one
INSERT INTO users (username, password_hash)
VALUES ($1, $2)
RETURNING id, username, created_at;

-- name: LoginUser :one
SELECT id, username, password_hash, created_at
FROM users
WHERE username = $1;

-- name: GetUserByID :one
SELECT id, username, created_at
FROM users
WHERE id = $1;

-- name: UpdateUser :one
UPDATE users
SET username = $2
WHERE id = $1
RETURNING username;

-- name: DeleteUser :exec
DELETE FROM users
WHERE id = $1;
