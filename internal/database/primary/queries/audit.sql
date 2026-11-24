-- name: CreateAuditLog :exec
INSERT INTO audit_logs (actor_id, action, entity_type, entity_id, changes, trace_id)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: ListAuditLogs :many
-- Newest first; an empty filter matches everything.
SELECT * FROM audit_logs
WHERE (sqlc.arg(entity_type)::text = '' OR entity_type = sqlc.arg(entity_type))
  AND (sqlc.arg(entity_id)::text = '' OR entity_id = sqlc.arg(entity_id))
  AND (sqlc.arg(actor_id)::text = '' OR actor_id = sqlc.arg(actor_id))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg('limit') OFFSET sqlc.arg('offset');

-- name: CountAuditLogs :one
SELECT count(*) FROM audit_logs
WHERE (sqlc.arg(entity_type)::text = '' OR entity_type = sqlc.arg(entity_type))
  AND (sqlc.arg(entity_id)::text = '' OR entity_id = sqlc.arg(entity_id))
  AND (sqlc.arg(actor_id)::text = '' OR actor_id = sqlc.arg(actor_id));

-- name: CleanupAuditLogs :execrows
DELETE FROM audit_logs WHERE created_at < sqlc.arg(before);