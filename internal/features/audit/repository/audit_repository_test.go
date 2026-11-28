package repository

// =============================================================================
// TEST CASE OVERVIEW
// =============================================================================
//
// File: audit_repository_test.go
// Purpose: Verify what the audit queries decide on a real database: the actor and entity label each
//          entry is read with, and the list filters and sort.
// Type: Integration (PostgreSQL at TEST_DATABASE_URL; skipped when unset; every test rolls back)
//
// Test functions: 2
// Total scenarios: 12
//
// #   Test Case                                             Scenario                               Expected Result
// 1   TestAuditRepository_List_JoinsActorAndLabel           Entry by a live user about a user      actor set; label is the user's email
// 2   TestAuditRepository_List_JoinsActorAndLabel           Entry by a soft-deleted user           actor still set
// 3   TestAuditRepository_List_JoinsActorAndLabel           Entry of a console command             actor nil
// 4   TestAuditRepository_List_JoinsActorAndLabel           Entry about a role deleted since       label is the name the entry recorded
// 5   TestAuditRepository_List_JoinsActorAndLabel           Earlier entry of it without its name   label is the name its delete recorded
// 6   TestAuditRepository_List_Filters                      Two actions                            Entries of either action
// 7   TestAuditRepository_List_Filters                      from and to                            Entries inside the range, bounds included
// 8   TestAuditRepository_List_Filters                      sort_order=asc                         Oldest first
// 9   TestAuditRepository_List_Filters                      Search by actor email                  That actor's entries
// 10  TestAuditRepository_List_Filters                      Search by actor full name              That actor's entries
// 11  TestAuditRepository_List_Filters                      Search matching no actor               Nothing, total 0
// 12  TestAuditRepository_List_Filters                      Page of one                            One entry; total counts every match
//
// =============================================================================

import (
	"context"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"jungo/internal/database/primary"
	"jungo/internal/database/primary/dbtest"
	"jungo/internal/database/primary/sqlc"
	"jungo/internal/features/audit/domain"
)

// insertEntry stores an entry at createdAt and returns its id.
func insertEntry(t *testing.T, ctx context.Context, db *primary.DB, actor *uuid.UUID, action, entityType, entityID, changes string, createdAt time.Time) int64 {
	t.Helper()

	var id int64
	err := db.Executor(ctx).QueryRow(ctx,
		`INSERT INTO audit_logs (actor_uuid, action, entity_type, entity_id, changes, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		actor, action, entityType, entityID, changes, createdAt,
	).Scan(&id)
	if err != nil {
		t.Fatalf("insert audit entry: %v", err)
	}

	return id
}

// createUser creates a user and returns them.
func createUser(t *testing.T, ctx context.Context, db *primary.DB, email, first, last string) sqlc.User {
	t.Helper()

	u, err := db.Queries(ctx).CreateUser(ctx, sqlc.CreateUserParams{Email: email, PasswordHash: "x", FirstName: first, LastName: last, Status: 1})
	if err != nil {
		t.Fatalf("CreateUser(%s) error = %v", email, err)
	}

	return u
}

// ids returns the entries' ids in order.
func ids(entries []*domain.AuditLog) []int64 {
	out := make([]int64, len(entries))
	for i, e := range entries {
		out[i] = e.ID
	}

	return out
}

func TestAuditRepository_List_JoinsActorAndLabel(t *testing.T) {
	db := dbtest.Open(t)
	repo := NewAuditRepository(db)

	dbtest.InRollback(t, db, func(ctx context.Context) {
		now := time.Now()
		ann := createUser(t, ctx, db, "ann@audit-repo.test", "Ann", "Lee")
		gone := createUser(t, ctx, db, "gone@audit-repo.test", "Gone", "User")
		if _, err := db.Queries(ctx).DeleteUser(ctx, gone.UUID); err != nil {
			t.Fatalf("DeleteUser() error = %v", err)
		}

		deletedRole := uuid.New().String()
		byAnn := insertEntry(t, ctx, db, &ann.UUID, "update", "users", ann.UUID.String(), `{}`, now)
		byGone := insertEntry(t, ctx, db, &gone.UUID, "update", "users", ann.UUID.String(), `{}`, now)
		byConsole := insertEntry(t, ctx, db, nil, "update", "users", ann.UUID.String(), `{}`, now)
		rolePerms := insertEntry(t, ctx, db, &ann.UUID, "update", "roles", deletedRole,
			`{"permissions": {"before": [], "after": ["users:read"]}}`, now.Add(-time.Minute))
		roleGone := insertEntry(t, ctx, db, &ann.UUID, "delete", "roles", deletedRole,
			`{"name": {"before": "Old role", "after": null}}`, now)

		// Listed by entity, so entries other tests left behind cannot crowd these out.
		byID := map[int64]*domain.AuditLog{}
		for _, f := range []domain.AuditLogListFilter{
			{EntityType: "users", EntityID: ann.UUID.String(), Limit: 10},
			{EntityType: "roles", EntityID: deletedRole, Limit: 10},
		} {
			entries, _, err := repo.List(ctx, f)
			if err != nil {
				t.Fatalf("List() error = %v", err)
			}

			for _, e := range entries {
				byID[e.ID] = e
			}
		}

		annActor := &domain.Actor{UUID: ann.UUID, Email: ann.Email, FirstName: "Ann", LastName: "Lee"}
		tests := []struct {
			name      string
			id        int64
			wantActor *domain.Actor
			wantLabel *string
		}{
			{"entry by a live user about a user", byAnn, annActor, &ann.Email},
			{"entry by a soft-deleted user", byGone, &domain.Actor{UUID: gone.UUID, Email: gone.Email, FirstName: "Gone", LastName: "User"}, &ann.Email},
			{"entry of a console command", byConsole, nil, &ann.Email},
			{"entry about a role deleted since", roleGone, annActor, new("Old role")},
			{"earlier entry of that role, without its name", rolePerms, annActor, new("Old role")},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				e := byID[tt.id]
				if e == nil {
					t.Fatalf("entry %d not listed", tt.id)
				}

				if !reflect.DeepEqual(e.Actor, tt.wantActor) || !reflect.DeepEqual(e.EntityLabel, tt.wantLabel) {
					t.Errorf("entry %d actor = %+v, label = %v; want %+v, %v", tt.id, e.Actor, e.EntityLabel, tt.wantActor, tt.wantLabel)
				}
			})
		}
	})
}

func TestAuditRepository_List_Filters(t *testing.T) {
	db := dbtest.Open(t)
	repo := NewAuditRepository(db)

	dbtest.InRollback(t, db, func(ctx context.Context) {
		ann := createUser(t, ctx, db, "ann.filter@audit-repo.test", "Ann", "Nguyen")
		bob := createUser(t, ctx, db, "bob.filter@audit-repo.test", "Bob", "Tran")
		// Every entry is about one entity, so the filters below see only these four.
		entity := uuid.New().String()
		day := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
		e1 := insertEntry(t, ctx, db, &ann.UUID, "create", "users", entity, `{}`, day)
		e2 := insertEntry(t, ctx, db, &bob.UUID, "update", "users", entity, `{}`, day.Add(time.Hour))
		e3 := insertEntry(t, ctx, db, &ann.UUID, "set_roles", "users", entity, `{}`, day.Add(2*time.Hour))
		e4 := insertEntry(t, ctx, db, &bob.UUID, "delete", "users", entity, `{}`, day.Add(3*time.Hour))

		tests := []struct {
			name      string
			filter    domain.AuditLogListFilter
			want      []int64
			wantTotal int64
		}{
			{"two actions", domain.AuditLogListFilter{Actions: []string{"create", "delete"}}, []int64{e4, e1}, 2},
			{"from and to", domain.AuditLogListFilter{From: new(day.Add(time.Hour)), To: new(day.Add(2 * time.Hour))}, []int64{e3, e2}, 2},
			{"sort_order=asc", domain.AuditLogListFilter{Ascending: true}, []int64{e1, e2, e3, e4}, 4},
			{"search by actor email", domain.AuditLogListFilter{Search: "BOB.filter"}, []int64{e4, e2}, 2},
			{"search by actor full name", domain.AuditLogListFilter{Search: "ann nguyen"}, []int64{e3, e1}, 2},
			{"search matching no actor", domain.AuditLogListFilter{Search: "nobody"}, []int64{}, 0},
			{"page of one", domain.AuditLogListFilter{Limit: 1}, []int64{e4}, 4},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := tt.filter
				f.EntityType, f.EntityID = "users", entity
				if f.Limit == 0 {
					f.Limit = 10
				}

				entries, total, err := repo.List(ctx, f)
				if err != nil {
					t.Fatalf("List() error = %v", err)
				}

				if got := ids(entries); !slices.Equal(got, tt.want) || total != tt.wantTotal {
					t.Errorf("List(%s) = %v (total %d), want %v (total %d)", tt.name, got, total, tt.want, tt.wantTotal)
				}
			})
		}
	})
}
