package v1

import (
	"time"

	"github.com/google/uuid"

	"github.com/jun-develop/junkit/pagination"
	"github.com/jun-develop/junkit/slicex"

	"jungo/internal/features/audit/domain"
)

// ListAuditLogsRequest binds the query of GET /audit-logs; every filter is optional and action may
// repeat. from and to (RFC 3339) bound created_at, both inclusive (to at the precision sent, so end
// a day with .999999); search matches the actor's email or full name.
type ListAuditLogsRequest struct {
	pagination.PageRequest
	EntityType string `form:"entity_type" binding:"omitempty,oneof=users roles" example:"users"`
	EntityID   string `form:"entity_id" binding:"omitempty,max=64" example:"9b2f1c1e-8a1d-4f0e-9c1a-3d2b1e0f4a5b"`
	ActorUUID  string `form:"actor_uuid" binding:"omitempty,uuid" example:"9b2f1c1e-8a1d-4f0e-9c1a-3d2b1e0f4a5b"`
	// Action is singular, as its parameter, so validation errors name it "action[0]".
	Action    []string   `form:"action" binding:"omitempty,dive,oneof=create update delete set_roles change_password"`
	From      *time.Time `form:"from" example:"2026-11-01T00:00:00Z"`
	To        *time.Time `form:"to" example:"2026-11-30T23:59:59.999999Z"`
	Search    string     `form:"search" binding:"omitempty,max=100" example:"john"`
	SortOrder string     `form:"sort_order" binding:"omitempty,oneof=asc desc" example:"desc"`
}

// ToAuditLogListFilter converts ListAuditLogsRequest to the domain filter; newest first by default.
func ToAuditLogListFilter(req ListAuditLogsRequest) domain.AuditLogListFilter {
	var actorUUID *uuid.UUID
	if id, err := uuid.Parse(req.ActorUUID); err == nil {
		actorUUID = &id
	}

	return domain.AuditLogListFilter{
		EntityType: req.EntityType,
		EntityID:   req.EntityID,
		ActorUUID:  actorUUID,
		Actions:    req.Action,
		From:       req.From,
		To:         req.To,
		Search:     req.Search,
		Ascending:  req.SortOrder == "asc",
		Limit:      req.GetLimit(),
		Offset:     req.GetOffset(),
	}
}

// AuditLogResponse represents an audit entry. The enum tags list every action and entity type the
// features record; a feature recording a new one adds it there, or the docs turn it down. actor is
// the user actor_uuid names (deleted users included), null for a console command; entity_label names
// the entity for display (a user's email, a role's name), null if unknown.
type AuditLogResponse struct {
	ID          int64               `json:"id"`
	CreatedAt   time.Time           `json:"created_at"`
	ActorUUID   *uuid.UUID          `json:"actor_uuid"`
	Actor       *AuditActorResponse `json:"actor"`
	Action      string              `json:"action" enum:"create update delete set_roles change_password"`
	EntityType  string              `json:"entity_type" enum:"users roles"`
	EntityID    string              `json:"entity_id"`
	EntityLabel *string             `json:"entity_label"`
	Changes     map[string]any      `json:"changes"`
	TraceID     *string             `json:"trace_id"`
}

// AuditActorResponse is the user who made a change.
type AuditActorResponse struct {
	UUID      uuid.UUID `json:"uuid"`
	Email     string    `json:"email"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
}

// NewAuditLogResponse converts domain.AuditLog to AuditLogResponse.
func NewAuditLogResponse(l *domain.AuditLog) AuditLogResponse {
	var actor *AuditActorResponse
	if a := l.Actor; a != nil {
		actor = &AuditActorResponse{UUID: a.UUID, Email: a.Email, FirstName: a.FirstName, LastName: a.LastName}
	}

	return AuditLogResponse{
		ID:          l.ID,
		CreatedAt:   l.CreatedAt,
		ActorUUID:   l.ActorUUID,
		Actor:       actor,
		Action:      l.Action,
		EntityType:  l.EntityType,
		EntityID:    l.EntityID,
		EntityLabel: l.EntityLabel,
		Changes:     l.Changes,
		TraceID:     l.TraceID,
	}
}

// NewAuditLogResponseList converts a slice of domain.AuditLog to AuditLogResponse list.
func NewAuditLogResponseList(items []*domain.AuditLog) []AuditLogResponse {
	return slicex.Map(items, NewAuditLogResponse)
}
