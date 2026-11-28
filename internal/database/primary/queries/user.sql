-- name: CreateUser :one
INSERT INTO users (email, password_hash, first_name, last_name, phone_number, status)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetUserByUUID :one
SELECT * FROM users WHERE uuid = $1 AND deleted_at IS NULL;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1 AND deleted_at IS NULL;

-- name: ListUsersNewest :many
-- The list queries and CountUsers share one filter: search, status (NULL = any) and role_uuids
-- (NULL = any; otherwise users holding at least one of those roles).
SELECT * FROM users
WHERE deleted_at IS NULL
  AND (sqlc.arg(search)::text = '' OR email ILIKE '%' || sqlc.arg(search) || '%' OR first_name ILIKE '%' || sqlc.arg(search) || '%' OR last_name ILIKE '%' || sqlc.arg(search) || '%')
  AND (sqlc.narg(status)::smallint IS NULL OR status = sqlc.narg(status))
  AND (sqlc.narg(role_uuids)::uuid[] IS NULL OR EXISTS (
      SELECT 1 FROM user_roles ur JOIN roles r ON r.id = ur.role_id
      WHERE ur.user_id = users.id AND r.uuid = ANY(sqlc.narg(role_uuids)::uuid[])))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg('limit') OFFSET sqlc.arg('offset');

-- name: ListUsersOldest :many
SELECT * FROM users
WHERE deleted_at IS NULL
  AND (sqlc.arg(search)::text = '' OR email ILIKE '%' || sqlc.arg(search) || '%' OR first_name ILIKE '%' || sqlc.arg(search) || '%' OR last_name ILIKE '%' || sqlc.arg(search) || '%')
  AND (sqlc.narg(status)::smallint IS NULL OR status = sqlc.narg(status))
  AND (sqlc.narg(role_uuids)::uuid[] IS NULL OR EXISTS (
      SELECT 1 FROM user_roles ur JOIN roles r ON r.id = ur.role_id
      WHERE ur.user_id = users.id AND r.uuid = ANY(sqlc.narg(role_uuids)::uuid[])))
ORDER BY created_at, id
LIMIT sqlc.arg('limit') OFFSET sqlc.arg('offset');

-- name: ListUsersSorted :many
-- Sorted by email, first_name, last_name or status (sort_by; status 1 = active sorts before 2 =
-- inactive, as their names do), ties broken by id. Sorting by created_at uses
-- ListUsersNewest/Oldest instead, which idx_users_active_created_at serves.
SELECT * FROM users
WHERE deleted_at IS NULL
  AND (sqlc.arg(search)::text = '' OR email ILIKE '%' || sqlc.arg(search) || '%' OR first_name ILIKE '%' || sqlc.arg(search) || '%' OR last_name ILIKE '%' || sqlc.arg(search) || '%')
  AND (sqlc.narg(status)::smallint IS NULL OR status = sqlc.narg(status))
  AND (sqlc.narg(role_uuids)::uuid[] IS NULL OR EXISTS (
      SELECT 1 FROM user_roles ur JOIN roles r ON r.id = ur.role_id
      WHERE ur.user_id = users.id AND r.uuid = ANY(sqlc.narg(role_uuids)::uuid[])))
ORDER BY
    CASE WHEN NOT sqlc.arg(descending)::bool THEN
        CASE sqlc.arg(sort_by)::text WHEN 'email' THEN email WHEN 'first_name' THEN first_name WHEN 'last_name' THEN last_name WHEN 'status' THEN status::text END
    END ASC,
    CASE WHEN sqlc.arg(descending)::bool THEN
        CASE sqlc.arg(sort_by)::text WHEN 'email' THEN email WHEN 'first_name' THEN first_name WHEN 'last_name' THEN last_name WHEN 'status' THEN status::text END
    END DESC,
    CASE WHEN NOT sqlc.arg(descending)::bool THEN id END ASC,
    CASE WHEN sqlc.arg(descending)::bool THEN id END DESC
LIMIT sqlc.arg('limit') OFFSET sqlc.arg('offset');

-- name: CountUsers :one
SELECT count(*) FROM users
WHERE deleted_at IS NULL
  AND (sqlc.arg(search)::text = '' OR email ILIKE '%' || sqlc.arg(search) || '%' OR first_name ILIKE '%' || sqlc.arg(search) || '%' OR last_name ILIKE '%' || sqlc.arg(search) || '%')
  AND (sqlc.narg(status)::smallint IS NULL OR status = sqlc.narg(status))
  AND (sqlc.narg(role_uuids)::uuid[] IS NULL OR EXISTS (
      SELECT 1 FROM user_roles ur JOIN roles r ON r.id = ur.role_id
      WHERE ur.user_id = users.id AND r.uuid = ANY(sqlc.narg(role_uuids)::uuid[])));

-- name: ListRolesOfUsers :many
-- The roles of each user in user_uuids, by name, for the users of one page in one query.
SELECT u.uuid AS user_uuid, r.uuid, r.code, r.name, r.is_system
FROM user_roles ur
JOIN users u ON u.id = ur.user_id
JOIN roles r ON r.id = ur.role_id
WHERE u.uuid = ANY(sqlc.arg(user_uuids)::uuid[])
ORDER BY r.name, r.id;

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

-- name: UpdateUserPassword :execrows
UPDATE users SET password_hash = sqlc.arg(password_hash) WHERE id = sqlc.arg(id) AND deleted_at IS NULL;
