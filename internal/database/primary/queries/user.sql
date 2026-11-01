-- name: CreateUser :one
INSERT INTO users (email, password_hash, first_name, last_name, phone_number, status)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetUserByUUID :one
SELECT * FROM users WHERE uuid = $1 AND deleted_at IS NULL;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1 AND deleted_at IS NULL;

-- name: ListUsers :many
-- No count(*) OVER(): it makes Postgres read and sort every matching row to return one page.
SELECT * FROM users
WHERE deleted_at IS NULL
  AND (sqlc.arg(search)::text = '' OR email ILIKE '%' || sqlc.arg(search) || '%' OR first_name ILIKE '%' || sqlc.arg(search) || '%' OR last_name ILIKE '%' || sqlc.arg(search) || '%')
ORDER BY
    CASE WHEN sqlc.arg(sort_order)::text = 'asc' THEN created_at END ASC,
    CASE WHEN sqlc.arg(sort_order)::text = 'desc' OR sqlc.arg(sort_order)::text = '' THEN created_at END DESC
LIMIT sqlc.arg('limit') OFFSET sqlc.arg('offset');

-- name: CountUsers :one
SELECT count(*) FROM users
WHERE deleted_at IS NULL
  AND (sqlc.arg(search)::text = '' OR email ILIKE '%' || sqlc.arg(search) || '%' OR first_name ILIKE '%' || sqlc.arg(search) || '%' OR last_name ILIKE '%' || sqlc.arg(search) || '%');

-- name: UpdateUser :one
UPDATE users SET
    first_name   = COALESCE(sqlc.narg(first_name), first_name),
    last_name    = COALESCE(sqlc.narg(last_name), last_name),
    phone_number = NULLIF(COALESCE(sqlc.narg(phone_number), phone_number), ''),
    avatar_url   = NULLIF(COALESCE(sqlc.narg(avatar_url), avatar_url), ''),
    status       = COALESCE(sqlc.narg(status), status)
WHERE uuid = sqlc.arg(uuid) AND deleted_at IS NULL
RETURNING *;

-- name: DeleteUser :execrows
-- avatar_url is cleared because DeleteUser removes the file.
UPDATE users SET deleted_at = now(), avatar_url = NULL WHERE uuid = $1 AND deleted_at IS NULL;

-- name: GetUserIDByUUID :one
SELECT id FROM users WHERE uuid = $1 AND deleted_at IS NULL;

-- name: LockUserByUUID :one
-- Locks the user's row until the transaction ends, so changes to their roles wait for it.
SELECT id FROM users WHERE uuid = $1 AND deleted_at IS NULL FOR UPDATE;
