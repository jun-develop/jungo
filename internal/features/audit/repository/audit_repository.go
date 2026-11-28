package repository

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jun-develop/junkit/database"
	"github.com/jun-develop/junkit/slicex"

	"jungo/internal/database/primary"
	"jungo/internal/database/primary/sqlc"
	"jungo/internal/features/audit/domain"
)

// AuditRepository implements domain.AuditRepository.
type AuditRepository struct {
	db *primary.DB
}

// NewAuditRepository creates an AuditRepository backed by db.
func NewAuditRepository(db *primary.DB) *AuditRepository {
	return &AuditRepository{db: db}
}

// Create implements domain.AuditRepository; it joins the transaction in ctx.
func (r *AuditRepository) Create(ctx context.Context, entry *domain.AuditLog) error {
	changes, err := json.Marshal(entry.Changes)
	if err != nil {
		return wrap("create", err)
	}

	err = r.db.Queries(ctx).CreateAuditLog(ctx, sqlc.CreateAuditLogParams{
		ActorUUID:  entry.ActorUUID,
		Action:     entry.Action,
		EntityType: entry.EntityType,
		EntityID:   entry.EntityID,
		Changes:    changes,
		TraceID:    entry.TraceID,
	})
	if err != nil {
		return wrap("create", err)
	}

	return nil
}

// List implements domain.AuditRepository; it also returns the total count for pagination.
func (r *AuditRepository) List(ctx context.Context, filter domain.AuditLogListFilter) ([]*domain.AuditLog, int64, error) {
	queries := r.db.Queries(ctx)
	search := database.EscapeLike(filter.Search)

	// nil, not an empty array, is what the queries read as "any action".
	var actions []string
	if len(filter.Actions) > 0 {
		actions = filter.Actions
	}

	params := sqlc.ListAuditLogsNewestParams{
		EntityType:  filter.EntityType,
		EntityID:    filter.EntityID,
		ActorUUID:   filter.ActorUUID,
		Actions:     actions,
		CreatedFrom: filter.From,
		CreatedTo:   filter.To,
		Search:      search,
		Limit:       filter.Limit,
		Offset:      filter.Offset,
	}

	var rows []sqlc.ListAuditLogsNewestRow
	var err error
	if filter.Ascending {
		var oldest []sqlc.ListAuditLogsOldestRow
		oldest, err = queries.ListAuditLogsOldest(ctx, sqlc.ListAuditLogsOldestParams(params))
		rows = slicex.Map(oldest, func(row sqlc.ListAuditLogsOldestRow) sqlc.ListAuditLogsNewestRow {
			return sqlc.ListAuditLogsNewestRow(row)
		})
	} else {
		rows, err = queries.ListAuditLogsNewest(ctx, params)
	}

	if err != nil {
		return nil, 0, wrap("list", err)
	}

	total, err := queries.CountAuditLogs(ctx, sqlc.CountAuditLogsParams{
		EntityType:  params.EntityType,
		EntityID:    params.EntityID,
		ActorUUID:   params.ActorUUID,
		Actions:     params.Actions,
		CreatedFrom: params.CreatedFrom,
		CreatedTo:   params.CreatedTo,
		Search:      params.Search,
	})
	if err != nil {
		return nil, 0, wrap("count", err)
	}

	return slicex.Map(rows, mapAuditLog), total, nil
}

// CleanupLogs implements domain.AuditRepository.
func (r *AuditRepository) CleanupLogs(ctx context.Context, before time.Time) (int64, error) {
	n, err := r.db.Queries(ctx).CleanupAuditLogs(ctx, before)
	if err != nil {
		return 0, wrap("cleanup logs", err)
	}

	return n, nil
}

// mapAuditLog converts a listed row to the domain model.
func mapAuditLog(row sqlc.ListAuditLogsNewestRow) *domain.AuditLog {
	var changes map[string]any
	_ = json.Unmarshal(row.Changes, &changes)

	entry := &domain.AuditLog{
		ID:         row.ID,
		CreatedAt:  row.CreatedAt,
		ActorUUID:  row.ActorUUID,
		Action:     row.Action,
		EntityType: row.EntityType,
		EntityID:   row.EntityID,
		Changes:    changes,
		TraceID:    row.TraceID,
	}

	// The actor's columns come from one LEFT JOIN: all set or all NULL.
	if row.ActorUUID != nil && row.ActorEmail != nil {
		entry.Actor = &domain.Actor{UUID: *row.ActorUUID, Email: *row.ActorEmail, FirstName: *row.ActorFirstName, LastName: *row.ActorLastName}
	}

	if row.EntityLabel != "" {
		entry.EntityLabel = &row.EntityLabel
	}

	return entry
}

// wrap adds the failed operation to err; domain errors stay matchable with errors.Is/As.
var wrap = database.ErrorPrefixer("audit repository")
