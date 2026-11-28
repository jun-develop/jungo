package repository

// =============================================================================
// TEST CASE OVERVIEW
// =============================================================================
//
// File: user_repository_test.go
// Purpose: Verify what the user queries decide on a real database: the roles each user comes with,
//          and the status and role filters and status sort of the list.
// Type: Integration (PostgreSQL at TEST_DATABASE_URL; skipped when unset; every test rolls back)
//
// Test functions: 2
// Total scenarios: 9
//
// #  Test Case                                          Scenario                              Expected Result
// 1  TestUserRepository_List_FiltersAndSorts            No filter                             Every test user, newest first
// 2  TestUserRepository_List_FiltersAndSorts            status=inactive                       Only the inactive user
// 3  TestUserRepository_List_FiltersAndSorts            One role                              Only that role's holders
// 4  TestUserRepository_List_FiltersAndSorts            Two roles                             Holders of either, each once
// 5  TestUserRepository_List_FiltersAndSorts            Unknown role UUID                     No user, total 0
// 6  TestUserRepository_List_FiltersAndSorts            Role and status together              Users matching both
// 7  TestUserRepository_List_FiltersAndSorts            sort_by=status asc                    Active users before the inactive one
// 8  TestUserRepository_List_FiltersAndSorts            Page of one                           One user; total counts every match
// 9  TestUserRepository_GetByUUID_ReturnsRolesByName    User with two roles                   Roles sorted by name; a user without roles gets []
//
// =============================================================================

import (
	"context"
	"slices"
	"testing"

	"github.com/google/uuid"

	"jungo/internal/database/primary"
	"jungo/internal/database/primary/dbtest"
	"jungo/internal/database/primary/sqlc"
	"jungo/internal/features/user/domain"
)

// search matches only the users these tests create.
const search = "@user-repo.test"

// testUser creates a user named email with status and the roles roleIDs.
func testUser(t *testing.T, ctx context.Context, db *primary.DB, email string, status int16, roleIDs ...int64) uuid.UUID {
	t.Helper()

	q := db.Queries(ctx)
	u, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: email, PasswordHash: "x", FirstName: "Test", LastName: "User", Status: status})
	if err != nil {
		t.Fatalf("CreateUser(%s) error = %v", email, err)
	}

	if len(roleIDs) > 0 {
		if err := q.AddUserRoles(ctx, sqlc.AddUserRolesParams{UserID: u.ID, RoleIds: roleIDs}); err != nil {
			t.Fatalf("AddUserRoles(%s) error = %v", email, err)
		}
	}

	return u.UUID
}

// testRole creates a role with code and name.
func testRole(t *testing.T, ctx context.Context, db *primary.DB, code, name string) sqlc.Role {
	t.Helper()

	r, err := db.Queries(ctx).CreateRole(ctx, sqlc.CreateRoleParams{Code: code, Name: name})
	if err != nil {
		t.Fatalf("CreateRole(%s) error = %v", code, err)
	}

	return r
}

// emails returns the users' emails in order.
func emails(users []*domain.User) []string {
	out := make([]string, len(users))
	for i, u := range users {
		out[i] = u.Email
	}

	return out
}

func TestUserRepository_List_FiltersAndSorts(t *testing.T) {
	db := dbtest.Open(t)
	repo := NewUserRepository(db)

	dbtest.InRollback(t, db, func(ctx context.Context) {
		editor := testRole(t, ctx, db, "repo_editor", "Repo editor")
		viewer := testRole(t, ctx, db, "repo_viewer", "Repo viewer")
		// Created in this order, so newest first is d, c, b, a (same created_at; ties go by id).
		testUser(t, ctx, db, "a"+search, domain.UserStatusActive, editor.ID)
		testUser(t, ctx, db, "b"+search, domain.UserStatusInactive, editor.ID, viewer.ID)
		testUser(t, ctx, db, "c"+search, domain.UserStatusActive, viewer.ID)
		testUser(t, ctx, db, "d"+search, domain.UserStatusActive)

		inactive := domain.UserStatusInactive
		active := domain.UserStatusActive
		tests := []struct {
			name      string
			filter    domain.UserListFilter
			want      []string
			wantTotal int64
		}{
			{"no filter", domain.UserListFilter{}, []string{"d", "c", "b", "a"}, 4},
			{"status=inactive", domain.UserListFilter{Status: &inactive}, []string{"b"}, 1},
			{"one role", domain.UserListFilter{RoleUUIDs: []uuid.UUID{viewer.UUID}}, []string{"c", "b"}, 2},
			{"two roles", domain.UserListFilter{RoleUUIDs: []uuid.UUID{editor.UUID, viewer.UUID}}, []string{"c", "b", "a"}, 3},
			{"unknown role uuid", domain.UserListFilter{RoleUUIDs: []uuid.UUID{uuid.New()}}, []string{}, 0},
			{"role and status together", domain.UserListFilter{RoleUUIDs: []uuid.UUID{editor.UUID}, Status: &active}, []string{"a"}, 1},
			{"sort_by=status asc", domain.UserListFilter{SortBy: "status", SortOrder: "asc"}, []string{"a", "c", "d", "b"}, 4},
			{"page of one", domain.UserListFilter{Limit: 1}, []string{"d"}, 4},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := tt.filter
				f.Search = search
				if f.Limit == 0 {
					f.Limit = 10
				}

				users, total, err := repo.List(ctx, f)
				if err != nil {
					t.Fatalf("List() error = %v", err)
				}

				want := make([]string, len(tt.want))
				for i, w := range tt.want {
					want[i] = w + search
				}

				if got := emails(users); !slices.Equal(got, want) || total != tt.wantTotal {
					t.Errorf("List(%s) = %v (total %d), want %v (total %d)", tt.name, got, total, want, tt.wantTotal)
				}
			})
		}
	})
}

func TestUserRepository_GetByUUID_ReturnsRolesByName(t *testing.T) {
	db := dbtest.Open(t)
	repo := NewUserRepository(db)

	dbtest.InRollback(t, db, func(ctx context.Context) {
		zeta := testRole(t, ctx, db, "repo_zeta", "Zeta")
		alpha := testRole(t, ctx, db, "repo_alpha", "Alpha")
		withRoles := testUser(t, ctx, db, "roles"+search, domain.UserStatusActive, zeta.ID, alpha.ID)
		without := testUser(t, ctx, db, "none"+search, domain.UserStatusActive)

		user, err := repo.GetByUUID(ctx, withRoles)
		if err != nil {
			t.Fatalf("GetByUUID() error = %v", err)
		}

		want := []domain.UserRole{
			{UUID: alpha.UUID, Code: "repo_alpha", Name: "Alpha"},
			{UUID: zeta.UUID, Code: "repo_zeta", Name: "Zeta"},
		}
		if !slices.Equal(user.Roles, want) {
			t.Errorf("GetByUUID().Roles = %+v, want %+v", user.Roles, want)
		}

		user, err = repo.GetByUUID(ctx, without)
		if err != nil {
			t.Fatalf("GetByUUID() error = %v", err)
		}

		if user.Roles == nil || len(user.Roles) != 0 {
			t.Errorf("GetByUUID().Roles = %#v, want an empty, non-nil list", user.Roles)
		}
	})
}
