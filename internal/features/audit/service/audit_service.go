package service

import (
	"bytes"
	"context"
	"encoding/json"
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
		Changes:    diff(e.Before, e.After),
	}

	if a, ok := actor.From(ctx); ok {
		entry.ActorUUID = &a.UserUUID
	}

	if traceID := logger.GetTraceID(ctx); traceID != "" {
		entry.TraceID = &traceID
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

// diff returns {"before": old, "after": new} for each key of after (of before for a delete) whose
// value changed. Values compare as JSON, so a *string and a string holding the same text are equal.
func diff(before, after map[string]any) map[string]any {
	keys := after
	if after == nil {
		keys = before
	}

	changes := map[string]any{}
	for k := range keys {
		if b, a := before[k], after[k]; !jsonEqual(b, a) {
			changes[k] = map[string]any{"before": b, "after": a}
		}
	}

	return changes
}

// jsonEqual reports whether a and b encode to the same JSON.
func jsonEqual(a, b any) bool {
	x, errA := json.Marshal(a)
	y, errB := json.Marshal(b)

	return errA == nil && errB == nil && bytes.Equal(x, y)
}
