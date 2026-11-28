package service

// =============================================================================
// TEST CASE OVERVIEW
// =============================================================================
//
// File: access_service_test.go
// Purpose: Verify what AccessService decides about roles and permissions: input checks, that no
//          one grants or removes more access than they hold, system roles stay untouched, which
//          repository calls it makes, which caches it invalidates and that errors are returned.
// Type: Unit (Func-field fakes)
//
// Test functions: 19
// Total scenarios: 63
//
// #   Test Case                                                                      Scenario                                    Expected Result
// 1   TestAccessService_CheckPermissions_ReportsPermissionsMissingFromDatabase       Every permission in the database            No error
// 2   TestAccessService_CheckPermissions_ReportsPermissionsMissingFromDatabase       roles:assign missing                        Error naming roles:assign
// 3   TestAccessService_CheckPermissions_ReportsPermissionsMissingFromDatabase       Permissions unreadable                      Database error
// 4   TestAccessService_Permissions_LoadsThroughCache                                Cache loads from the repository             That user's codes
// 5   TestAccessService_Permissions_LoadsThroughCache                                Cache fails                                 Cache error
// 6   TestAccessService_IsPermission_ReportsCodesFeaturesUse                         Code a feature uses                         true
// 7   TestAccessService_IsPermission_ReportsCodesFeaturesUse                         Code of the access feature                  true
// 8   TestAccessService_IsPermission_ReportsCodesFeaturesUse                         Unknown code                                false
// 9   TestAccessService_IsPermission_ReportsCodesFeaturesUse                         Empty code                                  false
// 10  TestAccessService_ListPermissionGroups_GroupsDatabasePermissions               Permissions in two groups                   One group per group code
// 11  TestAccessService_ListPermissionGroups_GroupsDatabasePermissions               Permissions unreadable                      Database error
// 12  TestAccessService_CreateRole_CreatesAndGrantsPermissions                       With users:read                             Created, name trimmed; users:read granted; one audit entry
// 13  TestAccessService_CreateRole_CreatesAndGrantsPermissions                       Without permissions                         Created; nothing granted; one audit entry
// 14  TestAccessService_CreateRole_RejectsInvalidCode                                Empty code                                  ErrInvalidRoleCode
// 15  TestAccessService_CreateRole_RejectsInvalidCode                                Upper-case letter                           ErrInvalidRoleCode
// 16  TestAccessService_CreateRole_RejectsInvalidCode                                Dash                                        ErrInvalidRoleCode
// 17  TestAccessService_CreateRole_RejectsInvalidCode                                Digit                                       ErrInvalidRoleCode
// 18  TestAccessService_CreateRole_RejectsInvalidInput                               Name of spaces only                         ErrInvalidRoleName
// 19  TestAccessService_CreateRole_RejectsInvalidInput                               Permission the actor lacks                  ErrEscalation
// 20  TestAccessService_CreateRole_RejectsInvalidInput                               No actor in the context                     actor.ErrForbidden
// 21  TestAccessService_CreateRole_RejectsInvalidInput                               Repository reports the code taken           ErrRoleAlreadyExists
// 22  TestAccessService_CreateRole_RejectsInvalidInput                               Permissions unreadable                      Database error
// 23  TestAccessService_GetRole_LooksUpOneRoleWithUserCount                          Known role                                  Asks for that role only, with its user count
// 24  TestAccessService_GetRole_LooksUpOneRoleWithUserCount                          Unknown role                                ErrRoleNotFound
// 25  TestAccessService_GetRole_LooksUpOneRoleWithUserCount                          Roles unreadable                            Database error
// 26  TestAccessService_ListRoles_PassesFilterToRepository                           A page of roles                             Repository receives the filter; its page and total returned
// 27  TestAccessService_ListRoles_PassesFilterToRepository                           Roles unreadable                            Database error
// 28  TestAccessService_RenameRole_UpdatesTrimmedName                                Name with surrounding spaces                Role's name updated, trimmed; one audit entry
// 29  TestAccessService_RenameRole_RejectsInvalidChanges                             Blank name                                  ErrInvalidRoleName
// 30  TestAccessService_RenameRole_RejectsInvalidChanges                             Unknown role                                ErrRoleNotFound
// 31  TestAccessService_RenameRole_RejectsInvalidChanges                             System role                                 ErrSystemRole
// 32  TestAccessService_RenameRole_RejectsInvalidChanges                             Role holding a permission the actor lacks   ErrEscalation
// 33  TestAccessService_RenameRole_RejectsInvalidChanges                             Lock fails                                  Database error
// 34  TestAccessService_ReplaceRolePermissions_StoresSortedCodesAndInvalidatesUsers  Codes unsorted, duplicated                  Stored sorted once; role's users invalidated; one audit entry
// 35  TestAccessService_ReplaceRolePermissions_ChecksEveryChange                     In the database, unused by the code         Allowed
// 36  TestAccessService_ReplaceRolePermissions_ChecksEveryChange                     Used by the code, not in the database       ErrUnknownPermission
// 37  TestAccessService_ReplaceRolePermissions_ChecksEveryChange                     Add a held one beside an unheld one         Allowed
// 38  TestAccessService_ReplaceRolePermissions_ChecksEveryChange                     Add a permission the actor lacks            ErrEscalation
// 39  TestAccessService_ReplaceRolePermissions_ChecksEveryChange                     Remove a permission the actor lacks         ErrEscalation
// 40  TestAccessService_ReplaceRolePermissions_ChecksEveryChange                     System role                                 ErrSystemRole
// 41  TestAccessService_ReplaceRolePermissions_ChecksEveryChange                     Unknown role                                ErrRoleNotFound
// 42  TestAccessService_ReplaceRolePermissions_ChecksEveryChange                     roles:update lost since the request         actor.ErrForbidden
// 43  TestAccessService_DeleteRole_DeletesAndInvalidatesUsers                        Role held by one user                       Role deleted; that user invalidated; one audit entry
// 44  TestAccessService_DeleteRole_InvalidatesEveryoneWhenRoleHasManyUsers           Exactly 100 users                           Each user invalidated
// 45  TestAccessService_DeleteRole_InvalidatesEveryoneWhenRoleHasManyUsers           101 users                                   Everyone invalidated at once
// 46  TestAccessService_DeleteRole_RejectsInvalidChanges                             System role                                 ErrSystemRole
// 47  TestAccessService_DeleteRole_RejectsInvalidChanges                             Role holding a permission the actor lacks   ErrEscalation
// 48  TestAccessService_DeleteRole_RejectsInvalidChanges                             roles:delete lost since the request         actor.ErrForbidden
// 49  TestAccessService_ListUserRoles_ReturnsRolesOfTheUser                          Known user                                  Asks for that user's roles
// 50  TestAccessService_ListUserRoles_ReturnsRolesOfTheUser                          Unknown user                                ErrUserNotFound
// 51  TestAccessService_ListUserRoles_ReturnsRolesOfTheUser                          User roles unreadable                       Database error
// 52  TestAccessService_SetUserRoles_ReplacesRolesAndInvalidatesUser                 Assign manager and extra (extra twice)      Each stored once; user invalidated; audit roles [] -> [extra manager]
// 53  TestAccessService_SetUserRoles_ReplacesRolesAndInvalidatesUser                 Clear a super_admin + manager user          No role stored; super_admin not checked; audit roles [manager] -> []
// 54  TestAccessService_SetUserRoles_RejectsInvalidChanges                           Actor changes their own roles               ErrCannotChangeOwnRoles
// 55  TestAccessService_SetUserRoles_RejectsInvalidChanges                           Unknown role                                ErrRoleNotFound
// 56  TestAccessService_SetUserRoles_RejectsInvalidChanges                           Unknown user                                ErrUserNotFound
// 57  TestAccessService_SetUserRoles_RejectsInvalidChanges                           Assign super_admin                          ErrSystemRole
// 58  TestAccessService_SetUserRoles_RejectsInvalidChanges                           Assign a role holding an unheld permission  ErrEscalation
// 59  TestAccessService_SetUserRoles_RejectsInvalidChanges                           Remove every role from a stronger user      actor.ErrCannotManageStrongerUser
// 60  TestAccessService_SetUserRoles_RejectsInvalidChanges                           Add a held role to a stronger user          actor.ErrCannotManageStrongerUser
// 61  TestAccessService_SetUserRoles_RejectsInvalidChanges                           Current roles unreadable                    Database error
// 62  TestAccessService_SetUserRoles_RejectsInvalidChanges                           Locking roles fails                         Database error
// 63  TestAccessService_SetUserRoles_RejectsInvalidChanges                           Wanted roles unreadable                     Database error
//
// =============================================================================

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"jungo/internal/common/actor"
	"jungo/internal/features/access/domain"
)

func TestAccessService_CheckPermissions_ReportsPermissionsMissingFromDatabase(t *testing.T) {
	t.Run("every permission in the database", func(t *testing.T) {
		s := newTestService(t, AccessServiceParams{
			Repo: &fakeRepository{ListPermissionsFunc: permissionsInDB(allPermissions...)},
		})

		wantErr(t, s.CheckPermissions(context.Background()), nil)
	})

	t.Run("roles:assign missing", func(t *testing.T) {
		migrated := slices.DeleteFunc(slices.Clone(allPermissions), func(code string) bool {
			return code == domain.RolesAssign
		})
		s := newTestService(t, AccessServiceParams{
			Repo: &fakeRepository{ListPermissionsFunc: permissionsInDB(migrated...)},
		})

		err := s.CheckPermissions(context.Background())

		if err == nil {
			t.Fatalf("CheckPermissions() error = nil, want an error naming %s", domain.RolesAssign)
		}

		if !strings.Contains(err.Error(), domain.RolesAssign) {
			t.Errorf("CheckPermissions() error = %q, want it to name %s", err, domain.RolesAssign)
		}
	})

	t.Run("permissions unreadable", func(t *testing.T) {
		repo := &fakeRepository{
			ListPermissionsFunc: func(context.Context) ([]domain.Permission, error) { return nil, errDB },
		}

		wantErr(t, newTestService(t, AccessServiceParams{Repo: repo}).CheckPermissions(context.Background()), errDB)
	})
}

func TestAccessService_Permissions_LoadsThroughCache(t *testing.T) {
	t.Run("cache loads from the repository", func(t *testing.T) {
		var askedFor int64
		repo := &fakeRepository{
			GetUserPermissionsFunc: func(_ context.Context, userID int64) ([]string, error) {
				askedFor = userID
				return []string{usersRead, usersUpdate}, nil
			},
		}

		got, err := newTestService(t, AccessServiceParams{Repo: repo}).Permissions(context.Background(), targetID)

		if err != nil {
			t.Fatalf("Permissions() error = %v", err)
		}

		if askedFor != targetID {
			t.Errorf("repository asked for user %d, want %d", askedFor, targetID)
		}

		if want := []string{usersRead, usersUpdate}; !slices.Equal(got, want) {
			t.Errorf("Permissions() = %v, want %v", got, want)
		}
	})

	t.Run("cache fails", func(t *testing.T) {
		s := newTestService(t, AccessServiceParams{Repo: &fakeRepository{}, Cache: &fakeCache{loadErr: errDB}})

		_, err := s.Permissions(context.Background(), targetID)

		wantErr(t, err, errDB)
	})
}

func TestAccessService_IsPermission_ReportsCodesFeaturesUse(t *testing.T) {
	tests := []struct {
		name string
		code string
		want bool
	}{
		{"code a feature uses", usersRead, true},
		{"code of the access feature", domain.RolesAssign, true},
		{"unknown code", "reports:read", false},
		{"empty code", "", false},
	}

	s := newTestService(t, AccessServiceParams{Repo: &fakeRepository{}})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := s.IsPermission(tt.code); got != tt.want {
				t.Errorf("IsPermission(%q) = %v, want %v", tt.code, got, tt.want)
			}
		})
	}
}

func TestAccessService_ListPermissionGroups_GroupsDatabasePermissions(t *testing.T) {
	t.Run("permissions in two groups", func(t *testing.T) {
		repo := &fakeRepository{
			ListPermissionsFunc: func(context.Context) ([]domain.Permission, error) {
				return []domain.Permission{
					{Code: usersRead, Group: "users"},
					{Code: domain.RolesRead, Group: "roles"},
					{Code: usersUpdate, Group: "users"},
				}, nil
			},
		}

		groups, err := newTestService(t, AccessServiceParams{Repo: repo}).ListPermissionGroups(context.Background())

		if err != nil {
			t.Fatalf("ListPermissionGroups() error = %v", err)
		}

		if len(groups) != 2 {
			t.Fatalf("ListPermissionGroups() returned %d groups, want 2 (one per group code)", len(groups))
		}

		got := map[string][]string{}
		for _, g := range groups {
			for _, p := range g.Permissions {
				got[g.Code] = append(got[g.Code], p.Code)
			}
		}

		want := map[string][]string{"users": {usersRead, usersUpdate}, "roles": {domain.RolesRead}}
		for group, codes := range want {
			if !slices.Equal(got[group], codes) {
				t.Errorf("group %q = %v, want %v", group, got[group], codes)
			}
		}
	})

	t.Run("permissions unreadable", func(t *testing.T) {
		repo := &fakeRepository{
			ListPermissionsFunc: func(context.Context) ([]domain.Permission, error) { return nil, errDB },
		}

		_, err := newTestService(t, AccessServiceParams{Repo: repo}).ListPermissionGroups(context.Background())

		wantErr(t, err, errDB)
	})
}

func TestAccessService_CreateRole_CreatesAndGrantsPermissions(t *testing.T) {
	tests := []struct {
		name        string
		permissions []string
	}{
		{"with users:read", []string{usersRead}},
		{"without permissions", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotCode, gotName string
			var grantedTo int64
			var granted []string
			repo := &fakeRepository{
				GetUserPermissionsFunc: holds(domain.RolesCreate, usersRead),
				ListPermissionsFunc:    permissionsInDB(allPermissions...),
				CreateRoleFunc: func(_ context.Context, code, name string) (*domain.Role, error) {
					gotCode, gotName = code, name
					return extra(), nil
				},
				ReplaceRolePermissionsFunc: func(_ context.Context, roleID int64, codes []string) error {
					grantedTo, granted = roleID, codes
					return nil
				},
				// The reloaded role carries its permissions; the one CreateRole returns does not.
				ListRolesFunc: rolesTable(extra(tt.permissions...)),
			}
			input := domain.CreateRoleInput{Code: "extra", Name: "  Extra  ", Permissions: tt.permissions}

			audit := &fakeRecorder{}

			role, err := newTestService(t, AccessServiceParams{Repo: repo, Audit: audit}).
				CreateRole(asActor(domain.RolesCreate), input)

			if err != nil {
				t.Fatalf("CreateRole() error = %v", err)
			}

			if gotCode != "extra" {
				t.Errorf("created role code = %q, want %q", gotCode, "extra")
			}

			if gotName != "Extra" {
				t.Errorf("created role name = %q, want %q (trimmed)", gotName, "Extra")
			}

			if !slices.Equal(granted, tt.permissions) {
				t.Errorf("granted permissions = %v, want %v", granted, tt.permissions)
			}

			if tt.permissions != nil && grantedTo != extra().ID {
				t.Errorf("permissions granted to role %d, want the created role %d", grantedTo, extra().ID)
			}

			if !slices.Equal(role.Permissions, tt.permissions) {
				t.Errorf("CreateRole() permissions = %v, want the reloaded role's %v", role.Permissions, tt.permissions)
			}

			wantEntry(t, audit, "create", "roles", extraUUID)
		})
	}
}

func TestAccessService_CreateRole_RejectsInvalidCode(t *testing.T) {
	tests := []struct {
		name string
		code string
	}{
		{"empty code", ""},
		{"upper-case letter", "Manager"},
		{"dash", "sales-team"},
		{"digit", "a1"},
	}

	s := newTestService(t, AccessServiceParams{Repo: &fakeRepository{}})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := s.CreateRole(asActor(domain.RolesCreate), domain.CreateRoleInput{Code: tt.code, Name: "X"})

			wantErr(t, err, domain.ErrInvalidRoleCode)
		})
	}
}

func TestAccessService_CreateRole_RejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		ctx   context.Context
		input domain.CreateRoleInput
		repo  *fakeRepository
		want  error
	}{
		{
			name:  "name of spaces only",
			ctx:   asActor(domain.RolesCreate),
			input: domain.CreateRoleInput{Code: "extra", Name: "  "},
			repo:  &fakeRepository{},
			want:  domain.ErrInvalidRoleName,
		},
		{
			name:  "permission the actor lacks",
			ctx:   asActor(domain.RolesCreate, usersRead),
			input: domain.CreateRoleInput{Code: "extra", Name: "X", Permissions: []string{usersDelete}},
			repo: &fakeRepository{
				GetUserPermissionsFunc: holds(domain.RolesCreate, usersRead),
				ListPermissionsFunc:    permissionsInDB(allPermissions...),
			},
			want: domain.ErrEscalation,
		},
		{
			// Outside a guarded route there is no actor: creating must fail, not succeed.
			name:  "no actor in the context",
			ctx:   context.Background(),
			input: domain.CreateRoleInput{Code: "extra", Name: "X", Permissions: []string{usersRead}},
			repo:  &fakeRepository{ListPermissionsFunc: permissionsInDB(allPermissions...)},
			want:  actor.ErrForbidden,
		},
		{
			name:  "repository reports the code taken",
			ctx:   asActor(domain.RolesCreate),
			input: domain.CreateRoleInput{Code: "extra", Name: "X"},
			repo: &fakeRepository{
				GetUserPermissionsFunc: holds(domain.RolesCreate),
				CreateRoleFunc: func(context.Context, string, string) (*domain.Role, error) {
					return nil, domain.ErrRoleAlreadyExists
				},
			},
			want: domain.ErrRoleAlreadyExists,
		},
		{
			name:  "permissions unreadable",
			ctx:   asActor(domain.RolesCreate),
			input: domain.CreateRoleInput{Code: "extra", Name: "X", Permissions: []string{usersRead}},
			repo: &fakeRepository{
				ListPermissionsFunc: func(context.Context) ([]domain.Permission, error) { return nil, errDB },
			},
			want: errDB,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newTestService(t, AccessServiceParams{Repo: tt.repo}).CreateRole(tt.ctx, tt.input)

			wantErr(t, err, tt.want)
		})
	}
}

func TestAccessService_GetRole_LooksUpOneRoleWithUserCount(t *testing.T) {
	t.Run("known role", func(t *testing.T) {
		var gotUIDs []uuid.UUID
		var gotCount bool
		repo := &fakeRepository{
			ListRolesFunc: func(_ context.Context, uids []uuid.UUID, countUsers bool) ([]*domain.Role, error) {
				gotUIDs, gotCount = uids, countUsers
				return []*domain.Role{manager()}, nil
			},
		}

		role, err := newTestService(t, AccessServiceParams{Repo: repo}).GetRole(context.Background(), managerUUID)

		if err != nil {
			t.Fatalf("GetRole() error = %v", err)
		}

		if !slices.Equal(gotUIDs, []uuid.UUID{managerUUID}) {
			t.Errorf("repository asked for roles %v, want only %s", gotUIDs, managerUUID)
		}

		if !gotCount {
			t.Error("repository asked without user counts, want with")
		}

		if role.UUID != managerUUID {
			t.Errorf("GetRole() returned role %s, want %s", role.UUID, managerUUID)
		}
	})

	t.Run("unknown role", func(t *testing.T) {
		s := newTestService(t, AccessServiceParams{Repo: &fakeRepository{ListRolesFunc: rolesTable(manager())}})

		_, err := s.GetRole(context.Background(), uuid.New())

		wantErr(t, err, domain.ErrRoleNotFound)
	})

	t.Run("roles unreadable", func(t *testing.T) {
		repo := &fakeRepository{
			ListRolesFunc: func(context.Context, []uuid.UUID, bool) ([]*domain.Role, error) { return nil, errDB },
		}

		_, err := newTestService(t, AccessServiceParams{Repo: repo}).GetRole(context.Background(), managerUUID)

		wantErr(t, err, errDB)
	})
}

func TestAccessService_ListRoles_PassesFilterToRepository(t *testing.T) {
	t.Run("a page of roles", func(t *testing.T) {
		filter := domain.RoleListFilter{Search: "man", SortBy: "user_count", SortOrder: "asc", Limit: 10, Offset: 10}
		var got domain.RoleListFilter
		repo := &fakeRepository{
			ListRolesPageFunc: func(_ context.Context, f domain.RoleListFilter) ([]*domain.Role, int64, error) {
				got = f
				return []*domain.Role{manager()}, 11, nil
			},
		}

		roles, total, err := newTestService(t, AccessServiceParams{Repo: repo}).ListRoles(context.Background(), filter)

		if err != nil {
			t.Fatalf("ListRoles() error = %v", err)
		}

		if got != filter {
			t.Errorf("repository received %+v, want %+v", got, filter)
		}

		if len(roles) != 1 || total != 11 {
			t.Errorf("ListRoles() = %d roles, total %d; want 1, total 11", len(roles), total)
		}
	})

	t.Run("roles unreadable", func(t *testing.T) {
		repo := &fakeRepository{
			ListRolesPageFunc: func(context.Context, domain.RoleListFilter) ([]*domain.Role, int64, error) { return nil, 0, errDB },
		}

		_, _, err := newTestService(t, AccessServiceParams{Repo: repo}).ListRoles(context.Background(), domain.RoleListFilter{Limit: 10})

		wantErr(t, err, errDB)
	})
}

func TestAccessService_RenameRole_UpdatesTrimmedName(t *testing.T) {
	var gotID int64
	var gotName string
	repo := &fakeRepository{
		GetUserPermissionsFunc: holds(domain.RolesUpdate, usersRead),
		ListRolesFunc:          rolesTable(manager(usersRead)),
		UpdateRoleNameFunc: func(_ context.Context, roleID int64, name string) error {
			gotID, gotName = roleID, name
			return nil
		},
	}
	audit := &fakeRecorder{}
	s := newTestService(t, AccessServiceParams{Repo: repo, Audit: audit})

	_, err := s.RenameRole(asActor(domain.RolesUpdate), managerUUID, "  Team Lead  ")

	if err != nil {
		t.Fatalf("RenameRole() error = %v", err)
	}

	if gotID != manager().ID {
		t.Errorf("renamed role ID = %d, want %d", gotID, manager().ID)
	}

	if gotName != "Team Lead" {
		t.Errorf("new name = %q, want %q (trimmed)", gotName, "Team Lead")
	}

	wantEntry(t, audit, "update", "roles", managerUUID)
}

func TestAccessService_RenameRole_RejectsInvalidChanges(t *testing.T) {
	// The actor holds users:read but not users:delete. A row without newName renames to "Boss".
	tests := []struct {
		name      string
		role      uuid.UUID
		newName   string
		breakRepo func(r *fakeRepository)
		want      error
	}{
		{name: "blank name", role: managerUUID, newName: "   ", want: domain.ErrInvalidRoleName},
		{name: "unknown role", role: uuid.New(), want: domain.ErrRoleNotFound},
		{name: "system role", role: superAdminUUID, want: domain.ErrSystemRole},
		{name: "role holding a permission the actor lacks", role: extraUUID, want: domain.ErrEscalation},
		{
			name: "lock fails",
			role: managerUUID,
			breakRepo: func(r *fakeRepository) {
				r.LockRolesFunc = func(context.Context, []uuid.UUID) error { return errDB }
			},
			want: errDB,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &fakeRepository{
				GetUserPermissionsFunc: holds(domain.RolesUpdate, usersRead),
				ListRolesFunc:          rolesTable(superAdmin(), manager(usersRead), extra(usersRead, usersDelete)),
			}
			if tt.breakRepo != nil {
				tt.breakRepo(repo)
			}

			if tt.newName == "" {
				tt.newName = "Boss"
			}

			_, err := newTestService(t, AccessServiceParams{Repo: repo}).
				RenameRole(asActor(domain.RolesUpdate), tt.role, tt.newName)

			wantErr(t, err, tt.want)
		})
	}
}

func TestAccessService_ReplaceRolePermissions_StoresSortedCodesAndInvalidatesUsers(t *testing.T) {
	var gotID int64
	var stored []string
	var gotLimit int32
	repo := &fakeRepository{
		GetUserPermissionsFunc: holds(domain.RolesUpdate, usersRead, usersUpdate),
		ListPermissionsFunc:    permissionsInDB(allPermissions...),
		ListRolesFunc:          rolesTable(manager()),
		ReplaceRolePermissionsFunc: func(_ context.Context, roleID int64, codes []string) error {
			gotID, stored = roleID, codes
			return nil
		},
		ListUserIDsByRoleFunc: func(_ context.Context, _ int64, limit int32) ([]int64, error) {
			gotLimit = limit
			return []int64{targetID}, nil
		},
	}
	cache := &fakeCache{}
	audit := &fakeRecorder{}
	codes := []string{usersUpdate, usersRead, usersRead}

	_, err := newTestService(t, AccessServiceParams{Repo: repo, Cache: cache, Audit: audit}).
		ReplaceRolePermissions(asActor(domain.RolesUpdate), managerUUID, codes)

	if err != nil {
		t.Fatalf("ReplaceRolePermissions() error = %v", err)
	}

	if gotID != manager().ID {
		t.Errorf("changed role ID = %d, want %d", gotID, manager().ID)
	}

	if want := []string{usersRead, usersUpdate}; !slices.Equal(stored, want) {
		t.Errorf("stored codes = %v, want %v (sorted, without duplicates)", stored, want)
	}

	if gotLimit != maxUsersToInvalidate+1 {
		t.Errorf("users listed with limit %d, want %d", gotLimit, maxUsersToInvalidate+1)
	}

	if !slices.Equal(cache.users, []int64{targetID}) {
		t.Errorf("invalidated users = %v, want [%d]", cache.users, targetID)
	}

	wantEntry(t, audit, "update", "roles", managerUUID)
}

func TestAccessService_ReplaceRolePermissions_ChecksEveryChange(t *testing.T) {
	// Unless a row says otherwise the role is manager without permissions, every permission the
	// code uses is in the database, and the actor holds roles:update and users:read only.
	tests := []struct {
		name   string
		role   uuid.UUID
		stored *domain.Role
		codes  []string
		inDB   []string
		holds  []string
		want   error
	}{
		{
			name:  "in the database, unused by the code",
			codes: []string{"reports:read"},
			inDB:  append([]string{"reports:read"}, allPermissions...),
			holds: []string{domain.RolesUpdate, "reports:read"},
			want:  nil,
		},
		{
			name:  "used by the code, not in the database",
			codes: []string{usersDelete},
			inDB:  []string{usersRead},
			holds: []string{domain.RolesUpdate, usersDelete},
			want:  domain.ErrUnknownPermission,
		},
		{
			name:   "add a held one beside an unheld one",
			stored: manager(usersDelete),
			codes:  []string{usersRead, usersDelete},
			want:   nil,
		},
		{
			name:   "add a permission the actor lacks",
			stored: manager(usersRead),
			codes:  []string{usersRead, usersDelete},
			want:   domain.ErrEscalation,
		},
		{
			name:   "remove a permission the actor lacks",
			stored: manager(usersRead, usersDelete),
			codes:  []string{usersRead},
			want:   domain.ErrEscalation,
		},
		{name: "system role", role: superAdminUUID, codes: []string{usersRead}, want: domain.ErrSystemRole},
		{name: "unknown role", role: uuid.New(), codes: []string{usersRead}, want: domain.ErrRoleNotFound},
		{
			// The request's cached copy still holds roles:update; the database no longer does.
			name:  "roles:update lost since the request",
			codes: []string{usersRead},
			holds: []string{usersRead},
			want:  actor.ErrForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.role == uuid.Nil {
				tt.role = managerUUID
			}

			if tt.stored == nil {
				tt.stored = manager()
			}

			if tt.inDB == nil {
				tt.inDB = allPermissions
			}

			if tt.holds == nil {
				tt.holds = []string{domain.RolesUpdate, usersRead}
			}

			repo := &fakeRepository{
				GetUserPermissionsFunc:     holds(tt.holds...),
				ListPermissionsFunc:        permissionsInDB(tt.inDB...),
				ListRolesFunc:              rolesTable(superAdmin(), tt.stored),
				ReplaceRolePermissionsFunc: func(context.Context, int64, []string) error { return nil },
				ListUserIDsByRoleFunc:      func(context.Context, int64, int32) ([]int64, error) { return nil, nil },
			}

			_, err := newTestService(t, AccessServiceParams{Repo: repo}).
				ReplaceRolePermissions(asActor(domain.RolesUpdate), tt.role, tt.codes)

			wantErr(t, err, tt.want)
		})
	}
}

func TestAccessService_DeleteRole_DeletesAndInvalidatesUsers(t *testing.T) {
	var deleted int64
	var gotLimit int32
	repo := &fakeRepository{
		GetUserPermissionsFunc: holds(domain.RolesDelete, usersRead),
		ListRolesFunc:          rolesTable(manager(usersRead)),
		ListUserIDsByRoleFunc: func(_ context.Context, _ int64, limit int32) ([]int64, error) {
			gotLimit = limit
			return []int64{targetID}, nil
		},
		DeleteRoleFunc: func(_ context.Context, roleID int64) error {
			deleted = roleID
			return nil
		},
	}
	cache := &fakeCache{}
	audit := &fakeRecorder{}

	err := newTestService(t, AccessServiceParams{Repo: repo, Cache: cache, Audit: audit}).
		DeleteRole(asActor(domain.RolesDelete), managerUUID)

	if err != nil {
		t.Fatalf("DeleteRole() error = %v", err)
	}

	if deleted != manager().ID {
		t.Errorf("deleted role ID = %d, want %d", deleted, manager().ID)
	}

	if gotLimit != maxUsersToInvalidate+1 {
		t.Errorf("users listed with limit %d, want %d", gotLimit, maxUsersToInvalidate+1)
	}

	if !slices.Equal(cache.users, []int64{targetID}) {
		t.Errorf("invalidated users = %v, want [%d]", cache.users, targetID)
	}

	wantEntry(t, audit, "delete", "roles", managerUUID)
}

func TestAccessService_DeleteRole_InvalidatesEveryoneWhenRoleHasManyUsers(t *testing.T) {
	tests := []struct {
		name        string
		users       int
		wantPerUser int
		wantAll     int
	}{
		{"exactly maxUsersToInvalidate users", maxUsersToInvalidate, maxUsersToInvalidate, 0},
		{"one user more than maxUsersToInvalidate", maxUsersToInvalidate + 1, 0, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &fakeRepository{
				GetUserPermissionsFunc: holds(domain.RolesDelete),
				ListRolesFunc:          rolesTable(manager()),
				DeleteRoleFunc:         func(context.Context, int64) error { return nil },
				ListUserIDsByRoleFunc: func(context.Context, int64, int32) ([]int64, error) {
					ids := make([]int64, tt.users)
					for i := range ids {
						ids[i] = int64(1000 + i)
					}

					return ids, nil
				},
			}
			cache := &fakeCache{}

			err := newTestService(t, AccessServiceParams{Repo: repo, Cache: cache}).
				DeleteRole(asActor(domain.RolesDelete), managerUUID)

			if err != nil {
				t.Fatalf("DeleteRole() error = %v", err)
			}

			if len(cache.users) != tt.wantPerUser {
				t.Errorf("users invalidated one by one = %d, want %d", len(cache.users), tt.wantPerUser)
			}

			if cache.all != tt.wantAll {
				t.Errorf("InvalidateAll calls = %d, want %d", cache.all, tt.wantAll)
			}
		})
	}
}

func TestAccessService_DeleteRole_RejectsInvalidChanges(t *testing.T) {
	// manager grants users:delete, which the actor never holds.
	tests := []struct {
		name  string
		role  uuid.UUID
		holds []string
		want  error
	}{
		{"system role", superAdminUUID, []string{domain.RolesDelete, usersRead}, domain.ErrSystemRole},
		{
			"role holding a permission the actor lacks",
			managerUUID,
			[]string{domain.RolesDelete, usersRead},
			domain.ErrEscalation,
		},
		// The request's cached copy still holds roles:delete; the database no longer does.
		{"roles:delete lost since the request", managerUUID, []string{usersRead}, actor.ErrForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &fakeRepository{
				GetUserPermissionsFunc: holds(tt.holds...),
				ListRolesFunc:          rolesTable(superAdmin(), manager(usersRead, usersDelete)),
			}

			err := newTestService(t, AccessServiceParams{Repo: repo}).DeleteRole(asActor(domain.RolesDelete), tt.role)

			wantErr(t, err, tt.want)
		})
	}
}

func TestAccessService_ListUserRoles_ReturnsRolesOfTheUser(t *testing.T) {
	t.Run("known user", func(t *testing.T) {
		var askedFor int64
		repo := &fakeRepository{
			GetUserIDFunc: func(context.Context, uuid.UUID) (int64, error) { return targetID, nil },
			ListUserRolesFunc: func(_ context.Context, userID int64) ([]*domain.Role, error) {
				askedFor = userID
				return []*domain.Role{manager()}, nil
			},
		}

		_, err := newTestService(t, AccessServiceParams{Repo: repo}).ListUserRoles(context.Background(), targetUUID)

		if err != nil {
			t.Fatalf("ListUserRoles() error = %v", err)
		}

		if askedFor != targetID {
			t.Errorf("repository asked for the roles of user %d, want %d", askedFor, targetID)
		}
	})

	t.Run("unknown user", func(t *testing.T) {
		repo := &fakeRepository{
			GetUserIDFunc: func(context.Context, uuid.UUID) (int64, error) { return 0, domain.ErrUserNotFound },
		}

		_, err := newTestService(t, AccessServiceParams{Repo: repo}).ListUserRoles(context.Background(), uuid.New())

		wantErr(t, err, domain.ErrUserNotFound)
	})

	t.Run("user roles unreadable", func(t *testing.T) {
		repo := &fakeRepository{
			GetUserIDFunc:     func(context.Context, uuid.UUID) (int64, error) { return targetID, nil },
			ListUserRolesFunc: func(context.Context, int64) ([]*domain.Role, error) { return nil, errDB },
		}

		_, err := newTestService(t, AccessServiceParams{Repo: repo}).ListUserRoles(context.Background(), targetUUID)

		wantErr(t, err, errDB)
	})
}

func TestAccessService_SetUserRoles_ReplacesRolesAndInvalidatesUser(t *testing.T) {
	// super_admin grants users:delete, which the actor lacks: were the system role counted as a
	// change, the call would fail with ErrEscalation.
	lockedAdmin := superAdmin(usersDelete)
	tests := []struct {
		name    string
		current []*domain.Role
		wanted  []uuid.UUID
		wantIDs []int64
		// wantBefore and wantAfter are the role codes the audit entry records; system roles are left out.
		wantBefore, wantAfter []string
	}{
		{
			name:       "assign manager and extra (extra twice)",
			current:    []*domain.Role{lockedAdmin},
			wanted:     []uuid.UUID{managerUUID, extraUUID, extraUUID},
			wantIDs:    []int64{2, 3},
			wantBefore: []string{},
			wantAfter:  []string{"extra", "manager"},
		},
		{
			name:       "clear a super_admin + manager user",
			current:    []*domain.Role{lockedAdmin, manager(usersRead)},
			wanted:     []uuid.UUID{},
			wantIDs:    nil,
			wantBefore: []string{"manager"},
			wantAfter:  []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotUser int64
			var gotIDs []int64
			repo := &fakeRepository{
				GetActorAndTargetPermissionsFunc: actorAndTargetHold([]string{domain.RolesAssign, usersRead}, nil),
				LockUserFunc: func(context.Context, uuid.UUID) (int64, error) {
					return targetID, nil
				},
				ListUserRolesFunc: func(context.Context, int64) ([]*domain.Role, error) {
					return tt.current, nil
				},
				ListRolesFunc: rolesTable(lockedAdmin, manager(usersRead), extra()),
				ReplaceUserRolesFunc: func(_ context.Context, userID int64, roleIDs []int64) error {
					gotUser, gotIDs = userID, roleIDs
					return nil
				},
			}
			cache := &fakeCache{}
			audit := &fakeRecorder{}

			_, err := newTestService(t, AccessServiceParams{Repo: repo, Cache: cache, Audit: audit}).
				SetUserRoles(asActor(domain.RolesAssign), targetUUID, tt.wanted)

			if err != nil {
				t.Fatalf("SetUserRoles() error = %v", err)
			}

			if gotUser != targetID {
				t.Errorf("roles replaced for user %d, want %d", gotUser, targetID)
			}

			if !slices.Equal(gotIDs, tt.wantIDs) {
				t.Errorf("stored role IDs = %v, want %v", gotIDs, tt.wantIDs)
			}

			if !slices.Equal(cache.users, []int64{targetID}) {
				t.Errorf("invalidated users = %v, want [%d]", cache.users, targetID)
			}

			wantEntry(t, audit, "set_roles", "users", targetUUID)

			// Never nil: the entry shows [] for no role, not null.
			e := audit.entries[0]
			if before, after := e.Before["roles"], e.After["roles"]; !reflect.DeepEqual(before, tt.wantBefore) || !reflect.DeepEqual(after, tt.wantAfter) {
				t.Errorf("audit roles = %#v -> %#v, want %#v -> %#v", before, after, tt.wantBefore, tt.wantAfter)
			}
		})
	}
}

func TestAccessService_SetUserRoles_RejectsInvalidChanges(t *testing.T) {
	weakActor := []string{domain.RolesAssign, usersRead}
	strongTarget := []string{usersRead, usersDelete}
	strongManager := manager(strongTarget...)
	readOnlyExtra := extra(usersRead)
	tests := []struct {
		name      string
		user      uuid.UUID
		roles     []uuid.UUID
		current   []*domain.Role
		targetHas []string
		breakRepo func(r *fakeRepository)
		want      error
	}{
		{
			name:  "actor changes their own roles",
			user:  actorUUID,
			roles: []uuid.UUID{extraUUID},
			want:  domain.ErrCannotChangeOwnRoles,
		},
		{name: "unknown role", user: targetUUID, roles: []uuid.UUID{uuid.New()}, want: domain.ErrRoleNotFound},
		{name: "unknown user", user: uuid.New(), want: domain.ErrUserNotFound},
		{name: "assign super_admin", user: targetUUID, roles: []uuid.UUID{superAdminUUID}, want: domain.ErrSystemRole},
		{
			name:  "assign a role holding an unheld permission",
			user:  targetUUID,
			roles: []uuid.UUID{managerUUID},
			want:  domain.ErrEscalation,
		},
		{
			name:      "remove every role from a stronger user",
			user:      targetUUID,
			current:   []*domain.Role{strongManager},
			targetHas: strongTarget,
			want:      actor.ErrCannotManageStrongerUser,
		},
		{
			name:      "add a held role to a stronger user",
			user:      targetUUID,
			roles:     []uuid.UUID{managerUUID, extraUUID},
			current:   []*domain.Role{strongManager},
			targetHas: strongTarget,
			want:      actor.ErrCannotManageStrongerUser,
		},
		{
			name: "current roles unreadable",
			user: targetUUID,
			breakRepo: func(r *fakeRepository) {
				r.ListUserRolesFunc = func(context.Context, int64) ([]*domain.Role, error) { return nil, errDB }
			},
			want: errDB,
		},
		{
			name:  "locking roles fails",
			user:  targetUUID,
			roles: []uuid.UUID{extraUUID},
			breakRepo: func(r *fakeRepository) {
				r.LockRolesFunc = func(context.Context, []uuid.UUID) error { return errDB }
			},
			want: errDB,
		},
		{
			name:  "wanted roles unreadable",
			user:  targetUUID,
			roles: []uuid.UUID{extraUUID},
			breakRepo: func(r *fakeRepository) {
				r.ListRolesFunc = func(context.Context, []uuid.UUID, bool) ([]*domain.Role, error) { return nil, errDB }
			},
			want: errDB,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &fakeRepository{
				GetActorAndTargetPermissionsFunc: actorAndTargetHold(weakActor, tt.targetHas),
				LockUserFunc: func(_ context.Context, uid uuid.UUID) (int64, error) {
					if uid != targetUUID {
						return 0, domain.ErrUserNotFound
					}

					return targetID, nil
				},
				ListUserRolesFunc: func(context.Context, int64) ([]*domain.Role, error) { return tt.current, nil },
				ListRolesFunc:     rolesTable(superAdmin(), strongManager, readOnlyExtra),
			}
			if tt.breakRepo != nil {
				tt.breakRepo(repo)
			}

			_, err := newTestService(t, AccessServiceParams{Repo: repo}).
				SetUserRoles(asActor(weakActor...), tt.user, tt.roles)

			wantErr(t, err, tt.want)
		})
	}
}
