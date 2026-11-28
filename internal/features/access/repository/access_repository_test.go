package repository

// =============================================================================
// TEST CASE OVERVIEW
// =============================================================================
//
// File: access_repository_test.go
// Purpose: Verify what the access queries decide on a real database.
// Type: Integration (PostgreSQL at TEST_DATABASE_URL; skipped when unset; every test rolls back)
//
// Test functions: 2
// Total scenarios: 9
//
// #  Test Case                                              Scenario                            Expected Result
// 1  TestAccessRepository_ListRoles_CountsOnlyActiveUsers   A soft-deleted user is not counted  user_count 1
// 2  TestAccessRepository_ListRoles_CountsOnlyActiveUsers   No count without countUsers         user_count 0
// 3  TestAccessRepository_ListRolesPage_SearchesAndSorts    Search on code                      Matching roles, newest first
// 4  TestAccessRepository_ListRolesPage_SearchesAndSorts    Search on name                      The role named so
// 5  TestAccessRepository_ListRolesPage_SearchesAndSorts    sort_by=name asc                    By name
// 6  TestAccessRepository_ListRolesPage_SearchesAndSorts    sort_by=code desc                   By code, reversed
// 7  TestAccessRepository_ListRolesPage_SearchesAndSorts    sort_by=user_count desc             Most users first, with counts
// 8  TestAccessRepository_ListRolesPage_SearchesAndSorts    Page of one, second page            The second role; total counts every match
// 9  TestAccessRepository_ListRolesPage_SearchesAndSorts    Search matching nothing             No role, total 0
//
// =============================================================================

import (
	"context"
	"slices"
	"testing"

	"github.com/google/uuid"

	"jungo/internal/database/primary/dbtest"
	"jungo/internal/database/primary/sqlc"
	"jungo/internal/features/access/domain"
)

func TestAccessRepository_ListRoles_CountsOnlyActiveUsers(t *testing.T) {
	db := dbtest.Open(t)
	repo := NewAccessRepository(db)

	dbtest.InRollback(t, db, func(ctx context.Context) {
		q := db.Queries(ctx)

		role, err := repo.CreateRole(ctx, "count_test", "Count test")
		if err != nil {
			t.Fatalf("CreateRole() error = %v", err)
		}

		var deleted uuid.UUID
		for i, email := range []string{"kept@count.test", "deleted@count.test"} {
			u, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: email, PasswordHash: "x", FirstName: "A", LastName: "B", Status: 1})
			if err != nil {
				t.Fatalf("CreateUser() error = %v", err)
			}

			if err := q.AddUserRoles(ctx, sqlc.AddUserRolesParams{UserID: u.ID, RoleIds: []int64{role.ID}}); err != nil {
				t.Fatalf("AddUserRoles() error = %v", err)
			}

			if i == 1 {
				deleted = u.UUID
			}
		}

		if _, err := q.DeleteUser(ctx, deleted); err != nil {
			t.Fatalf("DeleteUser() error = %v", err)
		}

		tests := []struct {
			name       string
			countUsers bool
			want       int64
		}{
			{"a soft-deleted user is not counted", true, 1},
			{"no count without countUsers", false, 0},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				roles, err := repo.ListRoles(ctx, []uuid.UUID{role.UUID}, tt.countUsers)
				if err != nil {
					t.Fatalf("ListRoles() error = %v", err)
				}

				if len(roles) != 1 {
					t.Fatalf("ListRoles() returned %d roles, want 1", len(roles))
				}

				if roles[0].UserCount != tt.want {
					t.Errorf("user_count = %d, want %d", roles[0].UserCount, tt.want)
				}
			})
		}

	})
}

func TestAccessRepository_ListRolesPage_SearchesAndSorts(t *testing.T) {
	db := dbtest.Open(t)
	repo := NewAccessRepository(db)

	dbtest.InRollback(t, db, func(ctx context.Context) {
		q := db.Queries(ctx)
		// Created in this order (same created_at; ties go by id), with 0, 2 and 1 users.
		var roles []int64
		for _, r := range [][2]string{{"pg_beta", "Zulu pager"}, {"pg_alpha", "Yankee pager"}, {"pg_gamma", "Xray pager"}} {
			role, err := repo.CreateRole(ctx, r[0], r[1])
			if err != nil {
				t.Fatalf("CreateRole() error = %v", err)
			}

			roles = append(roles, role.ID)
		}

		for i, holds := range [][]int64{{roles[1]}, {roles[1], roles[2]}} {
			u, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: string(rune('a'+i)) + "@roles-page.test", PasswordHash: "x", FirstName: "A", LastName: "B", Status: 1})
			if err != nil {
				t.Fatalf("CreateUser() error = %v", err)
			}

			if err := q.AddUserRoles(ctx, sqlc.AddUserRolesParams{UserID: u.ID, RoleIds: holds}); err != nil {
				t.Fatalf("AddUserRoles() error = %v", err)
			}
		}

		tests := []struct {
			name      string
			filter    domain.RoleListFilter
			want      []string
			wantTotal int64
		}{
			{"search on code", domain.RoleListFilter{Search: "pg_", SortBy: "created_at"}, []string{"pg_gamma", "pg_alpha", "pg_beta"}, 3},
			{"search on name", domain.RoleListFilter{Search: "yankee", SortBy: "created_at"}, []string{"pg_alpha"}, 1},
			{"sort_by=name asc", domain.RoleListFilter{Search: "pager", SortBy: "name", SortOrder: "asc"}, []string{"pg_gamma", "pg_alpha", "pg_beta"}, 3},
			{"sort_by=code desc", domain.RoleListFilter{Search: "pager", SortBy: "code"}, []string{"pg_gamma", "pg_beta", "pg_alpha"}, 3},
			{"sort_by=user_count desc", domain.RoleListFilter{Search: "pager", SortBy: "user_count"}, []string{"pg_alpha", "pg_gamma", "pg_beta"}, 3},
			{"page of one, second page", domain.RoleListFilter{Search: "pager", SortBy: "name", SortOrder: "asc", Limit: 1, Offset: 1}, []string{"pg_alpha"}, 3},
			{"search matching nothing", domain.RoleListFilter{Search: "nothing-like-this"}, []string{}, 0},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := tt.filter
				if f.Limit == 0 {
					f.Limit = 10
				}

				got, total, err := repo.ListRolesPage(ctx, f)
				if err != nil {
					t.Fatalf("ListRolesPage() error = %v", err)
				}

				codes := make([]string, len(got))
				for i, r := range got {
					codes[i] = r.Code
				}

				if !slices.Equal(codes, tt.want) || total != tt.wantTotal {
					t.Errorf("ListRolesPage(%s) = %v (total %d), want %v (total %d)", tt.name, codes, total, tt.want, tt.wantTotal)
				}

				if tt.name == "sort_by=user_count desc" && (got[0].UserCount != 2 || got[1].UserCount != 1 || got[2].UserCount != 0) {
					t.Errorf("user counts = %d, %d, %d; want 2, 1, 0", got[0].UserCount, got[1].UserCount, got[2].UserCount)
				}
			})
		}
	})
}
