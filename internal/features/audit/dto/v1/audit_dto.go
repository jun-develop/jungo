package v1

import (
	"time"

	"github.com/google/uuid"

	"github.com/jun-develop/junkit/pagination"
	"github.com/jun-develop/junkit/slicex"

	"jungo/internal/features/audit/domain"
)

// ListAuditLogsRequest binds the query of GET /audit-logs; every filter is optional.
type ListAuditLogsRequest struct {
	pagination.Request
	EntityType string `form:"entity_type" binding:"omitempty,max=63" example:"users"`
	EntityID   string `form:"entity_id" binding:"omitempty,max=64" example:"9b2f1c1e-8a1d-4f0e-9c1a-3d2b1e0f4a5b"`
	ActorUUID  string `form:"actor_uuid" binding:"omitempty,uuid" example:"9b2f1c1e-8a1d-4f0e-9c1a-3d2b1e0f4a5b"`
}

// ToAuditLogListFilter converts ListAuditLogsRequest to the domain filter.
func ToAuditLogListFilter(req ListAuditLogsRequest) domain.AuditLogListFilter {
	var actorUUID *uuid.UUID
	if id, err := uuid.Parse(req.ActorUUID); err == nil {
		actorUUID = &id
	}

	return domain.AuditLogListFilter{
		EntityType: req.EntityType,
		EntityID:   req.EntityID,
		ActorUUID:  actorUUID,
		Limit:      req.GetLimit(),
		Offset:     req.GetOffset(),
	}
}

// AuditLogResponse represents an audit entry.
type AuditLogResponse struct {
	ID         int64          `json:"id"`
	CreatedAt  time.Time      `json:"created_at"`
	ActorUUID  *uuid.UUID     `json:"actor_uuid"`
	Action     string         `json:"action"`
	EntityType string         `json:"entity_type"`
	EntityID   string         `json:"entity_id"`
	Changes    map[string]any `json:"changes"`
	TraceID    *string        `json:"trace_id"`
}

// NewAuditLogResponse converts domain.AuditLog to AuditLogResponse.
func NewAuditLogResponse(l *domain.AuditLog) AuditLogResponse {
	return AuditLogResponse{
		ID:         l.ID,
		CreatedAt:  l.CreatedAt,
		ActorUUID:  l.ActorUUID,
		Action:     l.Action,
		EntityType: l.EntityType,
		EntityID:   l.EntityID,
		Changes:    l.Changes,
		TraceID:    l.TraceID,
	}
}

// NewAuditLogResponseList converts a slice of domain.AuditLog to AuditLogResponse list.
func NewAuditLogResponseList(items []*domain.AuditLog) []AuditLogResponse {
	return slicex.Map(items, NewAuditLogResponse)
}
