package service

import (
	"context"
	"time"

	"github.com/jun-develop/junkit/logger"

	"jungo/internal/common/actor"
	"jungo/internal/common/auditlog"
	"jungo/internal/features/audit/domain"
)

// AuditService implements domain.AuditService.
type AuditService struct {
	repo domain.AuditRepository
	now  func() time.Time
}

// NewAuditService creates an AuditService.
func NewAuditService(repo domain.AuditRepository) *AuditService {
	return &AuditService{repo: repo, now: time.Now}
}

// Record implements auditlog.Recorder: the actor is the logged-in user in ctx (none for a console
// command), and the trace ID links the entry to the request's technical logs.
func (s *AuditService) Record(ctx context.Context, e auditlog.Entry) error {
	entry := &domain.AuditLog{
		Action:     e.Action,
		EntityType: e.EntityType,
		EntityID:   e.EntityID,
		Changes:    e.Changes,
	}

	if a, ok := actor.From(ctx); ok {
		id := a.UserUUID.String()
		entry.ActorID = &id
	}

	if traceID := logger.GetTraceID(ctx); traceID != "" {
		entry.TraceID = &traceID
	}

	if entry.Changes == nil {
		entry.Changes = map[string]any{}
	}

	return s.repo.Create(ctx, entry)
}

// ListAuditLogs returns a page of entries, newest first; an entity_id needs its entity_type.
func (s *AuditService) ListAuditLogs(ctx context.Context, filter domain.AuditLogListFilter) ([]*domain.AuditLog, int64, error) {
	if filter.EntityID != "" && filter.EntityType == "" {
		return nil, 0, domain.ErrEntityTypeRequired
	}

	return s.repo.List(ctx, filter)
}

// CleanupLogs deletes the entries older than domain.Retention and returns how many.
func (s *AuditService) CleanupLogs(ctx context.Context) (int64, error) {
	return s.repo.CleanupLogs(ctx, s.now().Add(-domain.Retention))
}
