package domain

import (
	"context"
	"time"

	"github.com/google/uuid"

	"jungo/internal/common/auditlog"
)

// Retention is how long entries are kept; audit:cleanup-logs deletes older ones.
const Retention = 30 * 24 * time.Hour

// AuditLog is one recorded change. Actor and EntityLabel are read with it, never stored.
type AuditLog struct {
	ID         int64
	CreatedAt  time.Time
	ActorUUID  *uuid.UUID
	Action     string
	EntityType string
	EntityID   string
	Changes    map[string]any
	TraceID    *string

	// Actor is the user ActorUUID names, deleted ones included; nil without one.
	Actor *Actor
	// EntityLabel names the entity for display (a user's email, a role's name); nil if unknown.
	EntityLabel *string
}

// Actor is the user who made a change.
type Actor struct {
	UUID      uuid.UUID
	Email     string
	FirstName string
	LastName  string
}

// AuditLogListFilter selects entries; empty fields match everything.
type AuditLogListFilter struct {
	EntityType string
	EntityID   string
	ActorUUID  *uuid.UUID
	// Actions keeps the entries of any of these actions.
	Actions []string
	// From and To bound created_at, both inclusive.
	From *time.Time
	To   *time.Time
	// Search matches the actor's email or full name.
	Search string
	// Ascending lists oldest first instead of newest first.
	Ascending bool
	Limit     int32
	Offset    int32
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
