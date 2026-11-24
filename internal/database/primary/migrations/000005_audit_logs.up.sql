-- =============================================================================
-- AUDIT_LOGS TABLE
-- What changed, who changed it and when. The services write it through auditlog.Recorder, inside
-- the transaction that makes the change. Rows older than 30 days are deleted by audit:cleanup-logs.
-- =============================================================================

CREATE TABLE IF NOT EXISTS audit_logs (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_id    VARCHAR(64),
    action      VARCHAR(50) NOT NULL,
    entity_type VARCHAR(63) NOT NULL,
    entity_id   VARCHAR(64) NOT NULL,
    changes     JSONB NOT NULL DEFAULT '{}',
    trace_id    VARCHAR(64)
);

COMMENT ON COLUMN audit_logs.actor_id IS 'UUID of the logged-in user; NULL for a console command';
COMMENT ON COLUMN audit_logs.changes IS '{column: {"before": ..., "after": ...}} for each value changed; never secrets';

-- Lists page newest first within an entity or an actor; created_at alone serves audit:cleanup-logs.
CREATE INDEX IF NOT EXISTS idx_audit_logs_entity ON audit_logs (entity_type, entity_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit_logs (actor_id, created_at DESC, id DESC) WHERE actor_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs (created_at);

-- =============================================================================
-- PERMISSIONS
-- The code in internal/features/audit/domain/permission.go, granted to super_admin.
-- =============================================================================

INSERT INTO permissions (code, group_code) VALUES
    ('audit_logs:read', 'audit_logs')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_code)
SELECT r.id, p.code
FROM roles r
JOIN permissions p ON p.code = 'audit_logs:read'
WHERE r.code = 'super_admin'
ON CONFLICT DO NOTHING;
