-- name: CreateAuditLog :exec
INSERT INTO audit_logs (actor_uuid, action, entity_type, entity_id, changes, trace_id)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: ListAuditLogsNewest :many
-- Newest first. An empty filter matches everything; created_from and created_to are inclusive, and
-- search matches the actor's email or full name. The actor and the entity's label (a user's email, a
-- role's name; '' if unknown) are joined at read time, soft-deleted users included; a role deleted since keeps the
-- name the entry itself recorded, if any.
SELECT a.id, a.created_at, a.actor_uuid, a.action, a.entity_type, a.entity_id, a.changes, a.trace_id,
       au.email AS actor_email, au.first_name AS actor_first_name, au.last_name AS actor_last_name,
       COALESCE(CASE a.entity_type
           WHEN 'users' THEN eu.email
           WHEN 'roles' THEN COALESCE(er.name, (
               SELECT COALESCE(n.changes->'name'->>'after', n.changes->'name'->>'before') FROM audit_logs n
               WHERE n.entity_type = 'roles' AND n.entity_id = a.entity_id AND n.changes ? 'name'
               ORDER BY n.created_at DESC, n.id DESC LIMIT 1))
       END, '')::text AS entity_label
FROM audit_logs a
LEFT JOIN users au ON au.uuid = a.actor_uuid
LEFT JOIN users eu ON eu.uuid = CASE WHEN a.entity_type = 'users' THEN a.entity_id::uuid END
LEFT JOIN roles er ON er.uuid = CASE WHEN a.entity_type = 'roles' THEN a.entity_id::uuid END
WHERE (sqlc.arg(entity_type)::text = '' OR a.entity_type = sqlc.arg(entity_type))
  AND (sqlc.arg(entity_id)::text = '' OR a.entity_id = sqlc.arg(entity_id))
  AND (sqlc.narg(actor_uuid)::uuid IS NULL OR a.actor_uuid = sqlc.narg(actor_uuid))
  AND (sqlc.narg(actions)::text[] IS NULL OR a.action = ANY(sqlc.narg(actions)::text[]))
  AND (sqlc.narg(created_from)::timestamptz IS NULL OR a.created_at >= sqlc.narg(created_from))
  AND (sqlc.narg(created_to)::timestamptz IS NULL OR a.created_at <= sqlc.narg(created_to))
  AND (sqlc.arg(search)::text = '' OR au.email ILIKE '%' || sqlc.arg(search) || '%' OR (au.first_name || ' ' || au.last_name) ILIKE '%' || sqlc.arg(search) || '%')
ORDER BY a.created_at DESC, a.id DESC
LIMIT sqlc.arg('limit') OFFSET sqlc.arg('offset');

-- name: ListAuditLogsOldest :many
-- ListAuditLogsNewest, oldest first.
SELECT a.id, a.created_at, a.actor_uuid, a.action, a.entity_type, a.entity_id, a.changes, a.trace_id,
       au.email AS actor_email, au.first_name AS actor_first_name, au.last_name AS actor_last_name,
       COALESCE(CASE a.entity_type
           WHEN 'users' THEN eu.email
           WHEN 'roles' THEN COALESCE(er.name, (
               SELECT COALESCE(n.changes->'name'->>'after', n.changes->'name'->>'before') FROM audit_logs n
               WHERE n.entity_type = 'roles' AND n.entity_id = a.entity_id AND n.changes ? 'name'
               ORDER BY n.created_at DESC, n.id DESC LIMIT 1))
       END, '')::text AS entity_label
FROM audit_logs a
LEFT JOIN users au ON au.uuid = a.actor_uuid
LEFT JOIN users eu ON eu.uuid = CASE WHEN a.entity_type = 'users' THEN a.entity_id::uuid END
LEFT JOIN roles er ON er.uuid = CASE WHEN a.entity_type = 'roles' THEN a.entity_id::uuid END
WHERE (sqlc.arg(entity_type)::text = '' OR a.entity_type = sqlc.arg(entity_type))
  AND (sqlc.arg(entity_id)::text = '' OR a.entity_id = sqlc.arg(entity_id))
  AND (sqlc.narg(actor_uuid)::uuid IS NULL OR a.actor_uuid = sqlc.narg(actor_uuid))
  AND (sqlc.narg(actions)::text[] IS NULL OR a.action = ANY(sqlc.narg(actions)::text[]))
  AND (sqlc.narg(created_from)::timestamptz IS NULL OR a.created_at >= sqlc.narg(created_from))
  AND (sqlc.narg(created_to)::timestamptz IS NULL OR a.created_at <= sqlc.narg(created_to))
  AND (sqlc.arg(search)::text = '' OR au.email ILIKE '%' || sqlc.arg(search) || '%' OR (au.first_name || ' ' || au.last_name) ILIKE '%' || sqlc.arg(search) || '%')
ORDER BY a.created_at, a.id
LIMIT sqlc.arg('limit') OFFSET sqlc.arg('offset');

-- name: CountAuditLogs :one
-- The filter of ListAuditLogsNewest.
SELECT count(*) FROM audit_logs a
LEFT JOIN users au ON au.uuid = a.actor_uuid
WHERE (sqlc.arg(entity_type)::text = '' OR a.entity_type = sqlc.arg(entity_type))
  AND (sqlc.arg(entity_id)::text = '' OR a.entity_id = sqlc.arg(entity_id))
  AND (sqlc.narg(actor_uuid)::uuid IS NULL OR a.actor_uuid = sqlc.narg(actor_uuid))
  AND (sqlc.narg(actions)::text[] IS NULL OR a.action = ANY(sqlc.narg(actions)::text[]))
  AND (sqlc.narg(created_from)::timestamptz IS NULL OR a.created_at >= sqlc.narg(created_from))
  AND (sqlc.narg(created_to)::timestamptz IS NULL OR a.created_at <= sqlc.narg(created_to))
  AND (sqlc.arg(search)::text = '' OR au.email ILIKE '%' || sqlc.arg(search) || '%' OR (au.first_name || ' ' || au.last_name) ILIKE '%' || sqlc.arg(search) || '%');

-- name: CleanupAuditLogs :execrows
DELETE FROM audit_logs WHERE created_at < sqlc.arg(before);
