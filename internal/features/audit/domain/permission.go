package domain

// Permission codes ("resource:action") the audit feature checks; each must also be a row in the
// permissions table (migration 000005_audit_logs inserts it). The audit log is read only.
const (
	AuditLogsRead = "audit_logs:read"
)

// Permissions lists the audit feature's permission codes; the module provides them to the "permissions" Fx group.
var Permissions = []string{AuditLogsRead}
