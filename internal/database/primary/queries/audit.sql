-- name: CreateAuditLog :exec
INSERT INTO audit_logs (actor_uuid, action, entity_type, entity_id, changes, trace_id)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: ListAuditLogs :many
-- Newest first; an empty filter matches everything.
SELECT * FROM audit_logs
WHERE (sqlc.arg(entity_type)::text = '' OR entity_type = sqlc.arg(entity_type))
  AND (sqlc.arg(entity_id)::text = '' OR entity_id = sqlc.arg(entity_id))
  AND (sqlc.narg(actor_uuid)::uuid IS NULL OR actor_uuid = sqlc.narg(actor_uuid))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg('limit') OFFSET sqlc.arg('offset');

-- name: CountAuditLogs :one
SELECT count(*) FROM audit_logs
WHERE (sqlc.arg(entity_type)::text = '' OR entity_type = sqlc.arg(entity_type))
  AND (sqlc.arg(entity_id)::text = '' OR entity_id = sqlc.arg(entity_id))
  AND (sqlc.narg(actor_uuid)::uuid IS NULL OR actor_uuid = sqlc.narg(actor_uuid));

-- name: CleanupAuditLogs :execrows
DELETE FROM audit_logs WHERE created_at < sqlc.arg(before);