-- name: GetUserPermissions :one
SELECT f_user_permissions($1)::text[] AS permissions;

-- name: GetActorAndTargetPermissions :one
-- Both users' codes in one round trip, for "may the actor manage the target" checks.
SELECT f_user_permissions(sqlc.arg(actor_id))::text[]  AS actor_permissions,
       f_user_permissions(sqlc.arg(target_id))::text[] AS target_permissions;

-- name: ListPermissions :many
SELECT code, group_code FROM permissions ORDER BY group_code, code;

-- name: CreateRole :one
INSERT INTO roles (code, name) VALUES ($1, $2)
RETURNING *;

-- name: ListRoles :many
-- Every role, or only those in uuids when it is not null, with permissions; user_count is counted
-- only when count_users is true (0 otherwise), so lookups made under a lock skip the count.
SELECT
    r.id, r.uuid, r.code, r.name, r.is_system, r.created_at, r.updated_at,
    COALESCE(
        (SELECT array_agg(rp.permission_code ORDER BY rp.permission_code) FROM role_permissions rp WHERE rp.role_id = r.id),
        '{}'
    )::text[] AS permissions,
    CASE WHEN sqlc.arg(count_users)::boolean
         THEN (SELECT count(*) FROM user_roles ur WHERE ur.role_id = r.id)
         ELSE 0
    END::bigint AS user_count
FROM roles r
WHERE sqlc.narg(uuids)::uuid[] IS NULL OR r.uuid = ANY(sqlc.narg(uuids)::uuid[])
ORDER BY r.is_system DESC, r.code;

-- name: LockRoles :exec
-- Locks the roles' rows until the transaction ends, in id order so two lockers cannot deadlock.
SELECT id FROM roles WHERE uuid = ANY(sqlc.arg(uuids)::uuid[]) ORDER BY id FOR UPDATE;

-- name: UpdateRoleName :one
UPDATE roles SET name = sqlc.arg(name) WHERE id = sqlc.arg(id)
RETURNING *;

-- name: DeleteRole :execrows
DELETE FROM roles WHERE id = $1 AND NOT is_system;

-- name: DeleteRolePermissions :exec
DELETE FROM role_permissions WHERE role_id = $1;

-- name: AddRolePermissions :exec
INSERT INTO role_permissions (role_id, permission_code)
SELECT sqlc.arg(role_id)::bigint, unnest(sqlc.arg(codes)::text[])
ON CONFLICT DO NOTHING;

-- name: ListUserIDsByRole :many
SELECT user_id FROM user_roles WHERE role_id = sqlc.arg(role_id) LIMIT sqlc.arg(max_rows);

-- name: ListUserRoles :many
SELECT r.* FROM roles r
JOIN user_roles ur ON ur.role_id = r.id
WHERE ur.user_id = $1
ORDER BY r.is_system DESC, r.code;

-- name: DeleteUserNonSystemRoles :exec
DELETE FROM user_roles ur
USING roles r
WHERE ur.role_id = r.id AND ur.user_id = $1 AND NOT r.is_system;

-- name: AddUserRoles :exec
INSERT INTO user_roles (user_id, role_id)
SELECT sqlc.arg(user_id)::bigint, unnest(sqlc.arg(role_ids)::bigint[])
ON CONFLICT DO NOTHING;
