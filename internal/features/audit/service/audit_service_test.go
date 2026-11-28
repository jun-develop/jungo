package service

// =============================================================================
// TEST CASE OVERVIEW
// =============================================================================
//
// File: audit_service_test.go
// Purpose: Verify what AuditService decides: who and which trace an entry records, which list
//          filters are valid, and the cleanup cutoff.
// Type: Unit (Func-field fakes)
//
// Test functions: 4
// Total scenarios: 9
//
// #   Test Case                                              Scenario                              Expected Result
// 1   TestAuditService_Record_TakesActorAndTraceFromContext  Logged-in user updates, request trace  actor_uuid and trace_id set; only changed keys of After kept, as before/after
// 2   TestAuditService_Record_TakesActorAndTraceFromContext  Console command deletes (no actor)     actor_uuid and trace_id nil; Before's keys kept with after null
// 3   TestAuditService_Record_SkipsUnchangedValues           Before and After hold the same values  Nothing stored
// 4   TestAuditService_Record_SkipsUnchangedValues           Neither Before nor After (an event)    Stored with empty changes
// 5   TestAuditService_ListAuditLogs_ValidatesTheFilter      No filter                             Repository receives it
// 6   TestAuditService_ListAuditLogs_ValidatesTheFilter      entity_type and entity_id             Repository receives it
// 7   TestAuditService_ListAuditLogs_ValidatesTheFilter      Every other filter set                Repository receives it
// 8   TestAuditService_ListAuditLogs_ValidatesTheFilter      entity_id without entity_type         ErrEntityTypeRequired; repository not called
// 9   TestAuditService_CleanupLogs_DeletesPastRetention      Clock at a fixed time                 Repository receives now minus 30 days; its count returned
//
// =============================================================================

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/jun-develop/junkit/logger"

	"jungo/internal/common/actor"
	"jungo/internal/common/auditlog"
	"jungo/internal/features/audit/domain"
)

func TestAuditService_Record_TakesActorAndTraceFromContext(t *testing.T) {
	userUUID := uuid.New()
	tests := []struct {
		name  string
		ctx   context.Context
		entry auditlog.Entry
		want  domain.AuditLog
	}{
		{
			name: "logged-in user, request trace",
			ctx:  logger.WithTraceID(actor.With(context.Background(), &actor.Actor{UserUUID: userUUID}), "trace-1"),
			entry: auditlog.Entry{
				Action: "update", EntityType: "users", EntityID: "u-1",
				Before: map[string]any{"first_name": "Ann", "last_name": "Lee", "phone_number": new("1"), "status": 1},
				After:  map[string]any{"first_name": "Anna", "last_name": "Lee", "phone_number": "1"},
			},
			want: domain.AuditLog{
				ActorUUID: &userUUID, Action: "update", EntityType: "users", EntityID: "u-1",
				Changes: map[string]any{"first_name": map[string]any{"before": "Ann", "after": "Anna"}}, TraceID: new("trace-1"),
			},
		},
		{
			name:  "console command (no actor, no trace)",
			ctx:   context.Background(),
			entry: auditlog.Entry{Action: "delete", EntityType: "roles", EntityID: "r-1", Before: map[string]any{"name": "Ops"}},
			want: domain.AuditLog{
				Action: "delete", EntityType: "roles", EntityID: "r-1",
				Changes: map[string]any{"name": map[string]any{"before": "Ops", "after": nil}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got *domain.AuditLog
			repo := &fakeAuditRepository{CreateFunc: func(_ context.Context, entry *domain.AuditLog) error {
				got = entry
				return nil
			}}

			if err := NewAuditService(repo).Record(tt.ctx, tt.entry); err != nil {
				t.Fatalf("Record() error = %v", err)
			}

			if !reflect.DeepEqual(*got, tt.want) {
				t.Errorf("stored entry = %+v, want %+v", *got, tt.want)
			}
		})
	}
}

func TestAuditService_Record_SkipsUnchangedValues(t *testing.T) {
	tests := []struct {
		name      string
		entry     auditlog.Entry
		wantSaved bool
	}{
		{
			name: "before and after hold the same values",
			entry: auditlog.Entry{
				Action: "set_roles", EntityType: "users", EntityID: "u-1",
				Before: map[string]any{"roles": []string{"editor"}}, After: map[string]any{"roles": []string{"editor"}},
			},
		},
		{name: "neither before nor after (an event)", entry: auditlog.Entry{Action: "change_password", EntityType: "users", EntityID: "u-1"}, wantSaved: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var saved *domain.AuditLog
			repo := &fakeAuditRepository{CreateFunc: func(_ context.Context, entry *domain.AuditLog) error {
				saved = entry
				return nil
			}}

			if err := NewAuditService(repo).Record(context.Background(), tt.entry); err != nil {
				t.Fatalf("Record() error = %v", err)
			}

			if (saved != nil) != tt.wantSaved {
				t.Fatalf("Record(%+v) stored %v, want stored = %v", tt.entry, saved, tt.wantSaved)
			}

			if saved != nil && len(saved.Changes) != 0 {
				t.Errorf("stored changes = %v, want {}", saved.Changes)
			}
		})
	}
}

func TestAuditService_ListAuditLogs_ValidatesTheFilter(t *testing.T) {
	tests := []struct {
		name    string
		filter  domain.AuditLogListFilter
		wantErr error
	}{
		{"no filter", domain.AuditLogListFilter{Limit: 10}, nil},
		{"entity_type and entity_id", domain.AuditLogListFilter{EntityType: "users", EntityID: "u-1", Limit: 10}, nil},
		{
			"every other filter set",
			domain.AuditLogListFilter{
				ActorUUID: new(uuid.New()), Actions: []string{"create", "set_roles"}, From: new(time.Now().Add(-time.Hour)), To: new(time.Now()),
				Search: "ann", Ascending: true, Limit: 10,
			},
			nil,
		},
		{"entity_id without entity_type", domain.AuditLogListFilter{EntityID: "u-1", Limit: 10}, domain.ErrEntityTypeRequired},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var asked *domain.AuditLogListFilter
			repo := &fakeAuditRepository{ListFunc: func(_ context.Context, f domain.AuditLogListFilter) ([]*domain.AuditLog, int64, error) {
				asked = &f
				return nil, 0, nil
			}}

			_, _, err := NewAuditService(repo).ListAuditLogs(context.Background(), tt.filter)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ListAuditLogs() error = %v, want %v", err, tt.wantErr)
			}

			if tt.wantErr != nil && asked != nil {
				t.Errorf("repository asked %+v, want no call", *asked)
			}

			if tt.wantErr == nil && (asked == nil || !reflect.DeepEqual(*asked, tt.filter)) {
				t.Errorf("repository received %v, want %+v", asked, tt.filter)
			}
		})
	}
}

func TestAuditService_CleanupLogs_DeletesPastRetention(t *testing.T) {
	now := time.Date(2026, 11, 24, 3, 0, 0, 0, time.UTC)
	var before time.Time
	repo := &fakeAuditRepository{CleanupLogsFunc: func(_ context.Context, b time.Time) (int64, error) {
		before = b
		return 7, nil
	}}
	svc := NewAuditService(repo)
	svc.now = func() time.Time { return now }

	deleted, err := svc.CleanupLogs(context.Background())

	if err != nil {
		t.Fatalf("CleanupLogs() error = %v", err)
	}

	if want := now.Add(-30 * 24 * time.Hour); !before.Equal(want) {
		t.Errorf("deleted before %v, want %v", before, want)
	}

	if deleted != 7 {
		t.Errorf("CleanupLogs() = %d, want 7", deleted)
	}
}
