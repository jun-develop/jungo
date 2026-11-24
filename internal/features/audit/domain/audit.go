package domain

import (
	"context"
	"time"

	"github.com/google/uuid"

	"jungo/internal/common/auditlog"
)

// Retention is how long entries are kept; audit:cleanup-logs deletes older ones.
const Retention = 30 * 24 * time.Hour

// AuditLog is one recorded change.
type AuditLog struct {
	ID         int64
	CreatedAt  time.Time
	ActorUUID  *uuid.UUID
	Action     string
	EntityType string
	EntityID   string
	Changes    map[string]any
	TraceID    *string
}

// AuditLogListFilter selects entries; empty fields match everything.
type AuditLogListFilter struct {
	EntityType string
	EntityID   string
	ActorUUID  *uuid.UUID
	Limit      int32
	Offset     int32
}

// AuditRepository stores and reads the audit log.
type AuditRepository interface {
	Create(ctx context.Context, entry *AuditLog) error
	List(ctx context.Context, filter AuditLogListFilter) ([]*AuditLog, int64, error)
	CleanupLogs(ctx context.Context, before time.Time) (int64, error)
}

// AuditService records changes for the other features and reads the audit log.
type AuditService interface {
	auditlog.Recorder
	ListAuditLogs(ctx context.Context, filter AuditLogListFilter) ([]*AuditLog, int64, error)
	CleanupLogs(ctx context.Context) (int64, error)
}
