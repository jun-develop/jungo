package service

// =============================================================================
// TEST CASE OVERVIEW
// =============================================================================
//
// File: access_service_test.go
// Purpose: Verify roles and permissions: reading them, creating and changing roles, assigning
//          roles to users, and that no one can grant more access than they hold.
// Type: Unit (in-memory fakes from fakes_test.go)
//
// Test functions: 26
// Total scenarios: 63
//
// #   Test Case                                                                   Scenario                                               Expected Result
// 1   TestAccessService_CheckPermissions_ReportsPermissionsMissingFromDatabase    Every permission migrated                              No error
// 2   TestAccessService_CheckPermissions_ReportsPermissionsMissingFromDatabase    roles:assign missing from the database                 Error naming roles:assign
// 3   TestAccessService_Permissions_ReturnsPermissionsOfUsersRoles                User holding manager                                   Manager's permissions, sorted
// 4   TestAccessService_Permissions_ReturnsPermissionsOfUsersRoles                Permission cache fails                                 Cache error returned
// 5   TestAccessService_IsPermission_ReportsCodesFeaturesUse                      Code a feature uses                                    true
// 6   TestAccessService_IsPermission_ReportsCodesFeaturesUse                      Code of the access feature                             true
// 7   TestAccessService_IsPermission_ReportsCodesFeaturesUse                      Unknown code                                           false
// 8   TestAccessService_IsPermission_ReportsCodesFeaturesUse                      Empty code                                             false
// 9   TestAccessService_ListPermissionGroups_GroupsDatabasePermissions            Permissions in two groups                              One group per group code with its permissions
// 10  TestAccessService_CreateRole_RejectsInvalidCode                             Empty code                                             ErrInvalidRoleCode
// 11  TestAccessService_CreateRole_RejectsInvalidCode                             Upper-case letter                                      ErrInvalidRoleCode
// 12  TestAccessService_CreateRole_RejectsInvalidCode                             Dash                                                   ErrInvalidRoleCode
// 13  TestAccessService_CreateRole_RejectsInvalidCode                             Digit                                                  ErrInvalidRoleCode
// 14  TestAccessService_CreateRole_GrantsRequestedPermissions                     New role with users:read                               Role created holding users:read
// 15  TestAccessService_CreateRole_RejectsDuplicateCode                           Code already used                                      ErrRoleAlreadyExists
// 16  TestAccessService_CreateRole_RejectsBlankName                               Name of spaces only                                    ErrInvalidRoleName
// 17  TestAccessService_CreateRole_FailsClosedWithoutActor                        No actor in the context                                actor.ErrForbidden
// 18  TestAccessService_GetRole_RejectsUnknownRole                                Unknown role UUID                                      ErrRoleNotFound
// 19  TestAccessService_ListRoles_ReturnsPermissionsAndUserCounts                 Manager with one permission and two users              Every role; manager has its permission and user count 2
// 20  TestAccessService_RenameRole_ChangesOnlyDisplayName                         Name with surrounding spaces                           Name trimmed and changed; code unchanged
// 21  TestAccessService_RenameRole_RejectsInvalidInput                            Blank name                                             ErrInvalidRoleName
// 22  TestAccessService_RenameRole_RejectsInvalidInput                            Unknown role                                           ErrRoleNotFound
// 23  TestAccessService_ReplaceRolePermissions_ReplacesGrantsAndInvalidatesUsers  Codes unsorted and duplicated                          Stored sorted without duplicates; the role's user invalidated
// 24  TestAccessService_ReplaceRolePermissions_RejectsInvalidInput                Permission code with a typo                            ErrUnknownPermission
// 25  TestAccessService_ReplaceRolePermissions_RejectsInvalidInput                System role                                            ErrSystemRole
// 26  TestAccessService_ReplaceRolePermissions_RejectsInvalidInput                Unknown role                                           ErrRoleNotFound
// 27  TestAccessService_ReplaceRolePermissions_UsesPermissionsFromDatabase        In the database, not yet used by the code              Can be granted
// 28  TestAccessService_ReplaceRolePermissions_UsesPermissionsFromDatabase        Named by the code, missing from the database           ErrUnknownPermission
// 29  TestAccessService_DeleteRole_InvalidatesItsUsers                            Role held by one user                                  That user's cached permissions invalidated
// 30  TestAccessService_DeleteRole_InvalidatesEveryoneWhenRoleHasManyUsers        Exactly 100 users                                      Each user invalidated, not everyone
// 31  TestAccessService_DeleteRole_InvalidatesEveryoneWhenRoleHasManyUsers        101 users                                              Everyone's cache invalidated at once
// 32  TestAccessService_ListUserRoles_ReturnsUsersRoles                           User holding manager                                   [manager]
// 33  TestAccessService_ListUserRoles_ReturnsUsersRoles                           Unknown user                                           ErrUserNotFound
// 34  TestAccessService_SetUserRoles_ReplacesOnlyNonSystemRoles                   Assign manager and extra (extra twice)                 super_admin kept, manager and extra added; user invalidated
// 35  TestAccessService_SetUserRoles_ReplacesOnlyNonSystemRoles                   Clear roles of a super_admin + manager user            Only super_admin left
// 36  TestAccessService_SetUserRoles_RejectsUnknownRoleOrUser                     Unknown role                                           ErrRoleNotFound
// 37  TestAccessService_SetUserRoles_RejectsUnknownRoleOrUser                     Unknown user                                           ErrUserNotFound
// 38  TestAccessService_SetUserRoles_RejectsChangingOwnRoles                      Actor changes their own roles                          ErrCannotChangeOwnRoles
// 39  TestAccessService_SystemRoleIsImmutable                                     Rename super_admin                                     ErrSystemRole
// 40  TestAccessService_SystemRoleIsImmutable                                     Replace super_admin's permissions                      ErrSystemRole
// 41  TestAccessService_SystemRoleIsImmutable                                     Delete super_admin                                     ErrSystemRole
// 42  TestAccessService_SystemRoleIsImmutable                                     Assign super_admin to a user                           ErrSystemRole
// 43  TestAccessService_PreventsPrivilegeEscalation                               Create a role with an unheld permission                ErrEscalation
// 44  TestAccessService_PreventsPrivilegeEscalation                               Add an unheld permission to a role                     ErrEscalation
// 45  TestAccessService_PreventsPrivilegeEscalation                               Delete a role holding an unheld permission             ErrEscalation
// 46  TestAccessService_PreventsPrivilegeEscalation                               Rename a role holding an unheld permission             ErrEscalation
// 47  TestAccessService_PreventsPrivilegeEscalation                               Assign a role holding an unheld permission             ErrEscalation
// 48  TestAccessService_PreventsPrivilegeEscalation                               Remove every role from a stronger user                 actor.ErrCannotManageStrongerUser
// 49  TestAccessService_PreventsPrivilegeEscalation                               Add a fully held role to a stronger user               actor.ErrCannotManageStrongerUser
// 50  TestAccessService_PreventsPrivilegeEscalation                               Remove an unheld permission from a role                ErrEscalation
// 51  TestAccessService_PreventsPrivilegeEscalation                               Add a held permission beside an unheld one that stays  Allowed (only changes are checked)
// 52  TestAccessService_ReloadsActorPermissionsBeforeChanges                      Replace permissions after losing roles:update          actor.ErrForbidden (database wins over request copy)
// 53  TestAccessService_ReloadsActorPermissionsBeforeChanges                      Delete role after losing roles:delete                  actor.ErrForbidden (database wins over request copy)
// 54  TestAccessService_ReturnsRepositoryErrors                                   CheckPermissions, permissions unreadable               Repository error returned
// 55  TestAccessService_ReturnsRepositoryErrors                                   ListPermissionGroups, permissions unreadable           Repository error returned
// 56  TestAccessService_ReturnsRepositoryErrors                                   CreateRole with permissions, permissions unreadable    Repository error returned
// 57  TestAccessService_ReturnsRepositoryErrors                                   GetRole, roles unreadable                              Repository error returned
// 58  TestAccessService_ReturnsRepositoryErrors                                   ListRoles, roles unreadable                            Repository error returned
// 59  TestAccessService_ReturnsRepositoryErrors                                   RenameRole, lock fails                                 Repository error returned
// 60  TestAccessService_ReturnsRepositoryErrors                                   ListUserRoles, user roles unreadable                   Repository error returned
// 61  TestAccessService_ReturnsRepositoryErrors                                   SetUserRoles, current roles unreadable                 Repository error returned
// 62  TestAccessService_ReturnsRepositoryErrors                                   SetUserRoles, lock fails                               Repository error returned
// 63  TestAccessService_ReturnsRepositoryErrors                                   SetUserRoles, wanted roles unreadable                  Repository error returned
//
// =============================================================================

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"jungo/internal/common/actor"
	"jungo/internal/features/access/domain"
)

func TestAccessService_CheckPermissions_ReportsPermissionsMissingFromDatabase(t *testing.T) {
	t.Run("every permission migrated", func(t *testing.T) {
		s, _, _ := newTestService()

		if err := s.CheckPermissions(context.Background()); err != nil {
			t.Errorf("CheckPermissions() error = %v, want nil", err)
		}
	})

	t.Run("roles:assign missing from the database", func(t *testing.T) {
		s, repo, _ := newTestService()
		delete(repo.permissions, domain.RolesAssign)

		err := s.CheckPermissions(context.Background())

		if err == nil {
			t.Fatal("CheckPermissions() error = nil, want an error naming roles:assign")
		}

		if !strings.Contains(err.Error(), domain.RolesAssign) {
			t.Errorf("CheckPermissions() error = %q, want it to name %s", err, domain.RolesAssign)
		}
	})
}

func TestAccessService_Permissions_ReturnsPermissionsOfUsersRoles(t *testing.T) {
	t.Run("user holding manager", func(t *testing.T) {
		s, repo, _ := newTestService()
		repo.grants[managerRoleID] = []string{usersUpdate, usersRead}
		repo.userRoles[userA] = []int64{managerRoleID}

		got, err := s.Permissions(context.Background(), userA)

		if err != nil {
			t.Fatalf("Permissions() error = %v", err)
		}

		if want := []string{usersRead, usersUpdate}; !slices.Equal(got, want) {
			t.Errorf("Permissions() = %v, want %v", got, want)
		}
	})

	t.Run("permission cache fails", func(t *testing.T) {
		s, _, c := newTestService()
		errCache := errors.New("fake cache: unreachable")
		c.loadErr = errCache

		if _, err := s.Permissions(context.Background(), userA); !errors.Is(err, errCache) {
			t.Errorf("Permissions() error = %v, want the cache error", err)
		}
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

	s, _, _ := newTestService()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := s.IsPermission(tt.code); got != tt.want {
				t.Errorf("IsPermission(%q) = %v, want %v", tt.code, got, tt.want)
			}
		})
	}
}

func TestAccessService_ListPermissionGroups_GroupsDatabasePermissions(t *testing.T) {
	s, repo, _ := newTestService()
	repo.permissions = map[string]string{usersRead: "users", usersUpdate: "users", domain.RolesRead: "roles"}

	groups, err := s.ListPermissionGroups(context.Background())
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
	if len(got) != len(want) {
		t.Fatalf("groups = %v, want %v", got, want)
	}

	for group, codes := range want {
		if !slices.Equal(slices.Sorted(slices.Values(got[group])), codes) {
			t.Errorf("group %q = %v, want %v", group, got[group], codes)
		}
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

	s, repo, _ := newTestService()
	ctx := asActor(repo, allPermissions...)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := s.CreateRole(ctx, domain.CreateRoleInput{Code: tt.code, Name: "Name"}); !errors.Is(err, domain.ErrInvalidRoleCode) {
				t.Errorf("CreateRole(code %q) error = %v, want ErrInvalidRoleCode", tt.code, err)
			}
		})
	}
}

func TestAccessService_CreateRole_GrantsRequestedPermissions(t *testing.T) {
	s, repo, _ := newTestService()

	role, err := s.CreateRole(asActor(repo, allPermissions...), domain.CreateRoleInput{Code: "sales_team", Name: "Sales", Permissions: []string{usersRead}})

	if err != nil {
		t.Fatalf("CreateRole() error = %v", err)
	}

	if !slices.Equal(role.Permissions, []string{usersRead}) {
		t.Errorf("CreateRole() permissions = %v, want [users:read]", role.Permissions)
	}
}

func TestAccessService_CreateRole_RejectsDuplicateCode(t *testing.T) {
	s, repo, _ := newTestService()
	ctx := asActor(repo, allPermissions...)
	if _, err := s.CreateRole(ctx, domain.CreateRoleInput{Code: "sales_team", Name: "Sales"}); err != nil {
		t.Fatalf("setup: CreateRole() error = %v", err)
	}

	if _, err := s.CreateRole(ctx, domain.CreateRoleInput{Code: "sales_team", Name: "Sales"}); !errors.Is(err, domain.ErrRoleAlreadyExists) {
		t.Errorf("CreateRole(existing code) error = %v, want ErrRoleAlreadyExists", err)
	}
}

func TestAccessService_CreateRole_RejectsBlankName(t *testing.T) {
	s, repo, _ := newTestService()

	_, err := s.CreateRole(asActor(repo, allPermissions...), domain.CreateRoleInput{Code: "blank_name", Name: "  "})

	if !errors.Is(err, domain.ErrInvalidRoleName) {
		t.Errorf("CreateRole(blank name) error = %v, want ErrInvalidRoleName", err)
	}
}

func TestAccessService_CreateRole_FailsClosedWithoutActor(t *testing.T) {
	s, _, _ := newTestService()

	// Without an actor (not behind a guarded route) creating must fail, not succeed.
	_, err := s.CreateRole(context.Background(), domain.CreateRoleInput{Code: "no_actor", Name: "X", Permissions: []string{usersRead}})

	if !errors.Is(err, actor.ErrForbidden) {
		t.Errorf("CreateRole() without actor error = %v, want actor.ErrForbidden", err)
	}
}

func TestAccessService_GetRole_RejectsUnknownRole(t *testing.T) {
	s, _, _ := newTestService()

	if _, err := s.GetRole(context.Background(), uuid.New()); !errors.Is(err, domain.ErrRoleNotFound) {
		t.Errorf("GetRole(unknown) error = %v, want ErrRoleNotFound", err)
	}
}

func TestAccessService_ListRoles_ReturnsPermissionsAndUserCounts(t *testing.T) {
	s, repo, _ := newTestService()
	repo.grants[managerRoleID] = []string{usersRead}
	repo.userRoles[userB] = []int64{managerRoleID}
	repo.userRoles[userC] = []int64{managerRoleID}

	roles, err := s.ListRoles(context.Background())
	if err != nil {
		t.Fatalf("ListRoles() error = %v", err)
	}

	if want := []string{"super_admin", "manager"}; !slices.Equal(roleCodes(roles), want) {
		t.Fatalf("ListRoles() codes = %v, want %v", roleCodes(roles), want)
	}

	manager := roles[1]
	if !slices.Equal(manager.Permissions, []string{usersRead}) {
		t.Errorf("manager permissions = %v, want [users:read]", manager.Permissions)
	}

	if manager.UserCount != 2 {
		t.Errorf("manager user count = %d, want 2", manager.UserCount)
	}
}

func TestAccessService_RenameRole_ChangesOnlyDisplayName(t *testing.T) {
	s, repo, _ := newTestService()

	role, err := s.RenameRole(asActor(repo, domain.RolesUpdate), repo.roles[1].UUID, "  Team Lead  ")

	if err != nil {
		t.Fatalf("RenameRole() error = %v", err)
	}

	if role.Name != "Team Lead" {
		t.Errorf("RenameRole() name = %q, want %q (trimmed)", role.Name, "Team Lead")
	}

	if role.Code != "manager" {
		t.Errorf("RenameRole() code = %q, want %q (unchanged)", role.Code, "manager")
	}
}

func TestAccessService_RenameRole_RejectsInvalidInput(t *testing.T) {
	s, repo, _ := newTestService()
	ctx := asActor(repo, domain.RolesUpdate)
	tests := []struct {
		name    string
		role    uuid.UUID
		newName string
		want    error
	}{
		{"blank name", repo.roles[1].UUID, "   ", domain.ErrInvalidRoleName},
		{"unknown role", uuid.New(), "Boss", domain.ErrRoleNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := s.RenameRole(ctx, tt.role, tt.newName); !errors.Is(err, tt.want) {
				t.Errorf("RenameRole() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestAccessService_ReplaceRolePermissions_ReplacesGrantsAndInvalidatesUsers(t *testing.T) {
	s, repo, c := newTestService()
	repo.userRoles[userB] = []int64{managerRoleID}

	_, err := s.ReplaceRolePermissions(asActor(repo, allPermissions...), repo.roles[1].UUID, []string{usersUpdate, usersRead, usersRead})

	if err != nil {
		t.Fatalf("ReplaceRolePermissions() error = %v", err)
	}

	if want := []string{usersRead, usersUpdate}; !slices.Equal(repo.grants[managerRoleID], want) {
		t.Errorf("grants = %v, want %v (sorted, without duplicates)", repo.grants[managerRoleID], want)
	}

	if !slices.Equal(c.users, []int64{userB}) {
		t.Errorf("invalidated users = %v, want [20]", c.users)
	}
}

func TestAccessService_ReplaceRolePermissions_RejectsInvalidInput(t *testing.T) {
	s, repo, _ := newTestService()
	ctx := asActor(repo, allPermissions...)
	tests := []struct {
		name  string
		role  uuid.UUID
		codes []string
		want  error
	}{
		{"permission code with a typo", repo.roles[1].UUID, []string{"users:typo"}, domain.ErrUnknownPermission},
		{"system role", repo.roles[0].UUID, []string{usersRead}, domain.ErrSystemRole},
		{"unknown role", uuid.New(), []string{usersRead}, domain.ErrRoleNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := s.ReplaceRolePermissions(ctx, tt.role, tt.codes); !errors.Is(err, tt.want) {
				t.Errorf("ReplaceRolePermissions() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestAccessService_ReplaceRolePermissions_UsesPermissionsFromDatabase(t *testing.T) {
	t.Run("permission in the database but not yet used by the code", func(t *testing.T) {
		s, repo, _ := newTestService()
		repo.permissions["reports:read"] = "reports"

		_, err := s.ReplaceRolePermissions(asActor(repo, domain.RolesUpdate, "reports:read"), repo.roles[1].UUID, []string{"reports:read"})

		if err != nil {
			t.Errorf("ReplaceRolePermissions() error = %v, want nil (it can already be granted)", err)
		}
	})

	t.Run("permission named by the code but missing from the database", func(t *testing.T) {
		s, repo, _ := newTestService()
		delete(repo.permissions, usersDelete)

		_, err := s.ReplaceRolePermissions(asActor(repo, allPermissions...), repo.roles[1].UUID, []string{usersDelete})

		if !errors.Is(err, domain.ErrUnknownPermission) {
			t.Errorf("ReplaceRolePermissions() error = %v, want ErrUnknownPermission", err)
		}
	})
}

func TestAccessService_DeleteRole_InvalidatesItsUsers(t *testing.T) {
	s, repo, c := newTestService()
	repo.userRoles[userB] = []int64{managerRoleID}

	if err := s.DeleteRole(asActor(repo, domain.RolesDelete), repo.roles[1].UUID); err != nil {
		t.Fatalf("DeleteRole() error = %v", err)
	}

	if !slices.Equal(c.users, []int64{userB}) {
		t.Errorf("invalidated users = %v, want [20]", c.users)
	}
}

func TestAccessService_DeleteRole_InvalidatesEveryoneWhenRoleHasManyUsers(t *testing.T) {
	tests := []struct {
		name          string
		users         int
		wantPerUser   int
		wantAllCalled int
	}{
		{"exactly maxUsersToInvalidate users", maxUsersToInvalidate, maxUsersToInvalidate, 0},
		{"one user more than maxUsersToInvalidate", maxUsersToInvalidate + 1, 0, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, repo, c := newTestService()
			for i := range tt.users {
				repo.userRoles[int64(1000+i)] = []int64{managerRoleID}
			}

			if err := s.DeleteRole(asActor(repo, domain.RolesDelete), repo.roles[1].UUID); err != nil {
				t.Fatalf("DeleteRole() error = %v", err)
			}

			if len(c.users) != tt.wantPerUser {
				t.Errorf("users invalidated one by one = %d, want %d", len(c.users), tt.wantPerUser)
			}

			if c.all != tt.wantAllCalled {
				t.Errorf("InvalidateAll calls = %d, want %d", c.all, tt.wantAllCalled)
			}
		})
	}
}

func TestAccessService_ListUserRoles_ReturnsUsersRoles(t *testing.T) {
	t.Run("user holding manager", func(t *testing.T) {
		s, repo, _ := newTestService()
		repo.userRoles[userA] = []int64{managerRoleID}

		roles, err := s.ListUserRoles(context.Background(), userUUIDs[userA])

		if err != nil {
			t.Fatalf("ListUserRoles() error = %v", err)
		}

		if want := []string{"manager"}; !slices.Equal(roleCodes(roles), want) {
			t.Errorf("ListUserRoles() codes = %v, want %v", roleCodes(roles), want)
		}
	})

	t.Run("unknown user", func(t *testing.T) {
		s, _, _ := newTestService()

		if _, err := s.ListUserRoles(context.Background(), uuid.New()); !errors.Is(err, domain.ErrUserNotFound) {
			t.Errorf("ListUserRoles(unknown) error = %v, want ErrUserNotFound", err)
		}
	})
}

func TestAccessService_SetUserRoles_ReplacesOnlyNonSystemRoles(t *testing.T) {
	// newSetup gives userA super_admin (a system role) and an actor allowed to assign manager and extra.
	newSetup := func(t *testing.T) (*AccessService, *fakeRepository, *fakeCache, context.Context, *domain.Role) {
		t.Helper()
		s, repo, c := newTestService()
		repo.grants[managerRoleID] = []string{usersRead}
		extra, err := repo.CreateRole(context.Background(), "extra", "Extra")
		if err != nil {
			t.Fatalf("setup: CreateRole() error = %v", err)
		}

		repo.userRoles[userA] = []int64{superAdminRoleID}

		return s, repo, c, asActor(repo, domain.RolesAssign, usersRead), extra
	}

	t.Run("assign manager and extra (extra listed twice)", func(t *testing.T) {
		s, repo, c, ctx, extra := newSetup(t)

		roles, err := s.SetUserRoles(ctx, userUUIDs[userA], []uuid.UUID{repo.roles[1].UUID, extra.UUID, extra.UUID})

		if err != nil {
			t.Fatalf("SetUserRoles() error = %v", err)
		}

		if want := []string{"super_admin", "manager", "extra"}; !slices.Equal(roleCodes(roles), want) {
			t.Errorf("SetUserRoles() codes = %v, want %v (system role kept)", roleCodes(roles), want)
		}

		if !slices.Equal(c.users, []int64{userA}) {
			t.Errorf("invalidated users = %v, want [10]", c.users)
		}
	})

	t.Run("clear the roles of a user holding super_admin and manager", func(t *testing.T) {
		s, repo, _, ctx, _ := newSetup(t)
		repo.userRoles[userA] = []int64{superAdminRoleID, managerRoleID}

		roles, err := s.SetUserRoles(ctx, userUUIDs[userA], []uuid.UUID{})

		if err != nil {
			t.Fatalf("SetUserRoles() error = %v", err)
		}

		if want := []string{"super_admin"}; !slices.Equal(roleCodes(roles), want) {
			t.Errorf("SetUserRoles(empty) codes = %v, want %v", roleCodes(roles), want)
		}
	})
}

func TestAccessService_SetUserRoles_RejectsUnknownRoleOrUser(t *testing.T) {
	s, repo, _ := newTestService()
	ctx := asActor(repo, domain.RolesAssign, usersRead)
	tests := []struct {
		name  string
		user  uuid.UUID
		roles []uuid.UUID
		want  error
	}{
		{"unknown role", userUUIDs[userA], []uuid.UUID{uuid.New()}, domain.ErrRoleNotFound},
		{"unknown user", uuid.New(), nil, domain.ErrUserNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := s.SetUserRoles(ctx, tt.user, tt.roles); !errors.Is(err, tt.want) {
				t.Errorf("SetUserRoles() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestAccessService_SetUserRoles_RejectsChangingOwnRoles(t *testing.T) {
	s, repo, _ := newTestService()
	repo.actorPerms[userA] = []string{domain.RolesAssign, usersRead}
	self := actor.With(context.Background(), &actor.Actor{UserID: userA, UserUUID: userUUIDs[userA], Permissions: repo.actorPerms[userA]})

	_, err := s.SetUserRoles(self, userUUIDs[userA], []uuid.UUID{repo.roles[1].UUID})

	if !errors.Is(err, domain.ErrCannotChangeOwnRoles) {
		t.Errorf("SetUserRoles(own user) error = %v, want ErrCannotChangeOwnRoles", err)
	}
}

func TestAccessService_SystemRoleIsImmutable(t *testing.T) {
	s, repo, _ := newTestService()
	ctx := asActor(repo, domain.RolesUpdate, domain.RolesDelete, domain.RolesAssign, usersRead)
	super := repo.roles[0].UUID
	tests := []struct {
		name string
		call func() error
	}{
		{"rename", func() error { _, err := s.RenameRole(ctx, super, "Boss"); return err }},
		{"replace permissions", func() error { _, err := s.ReplaceRolePermissions(ctx, super, nil); return err }},
		{"delete", func() error { return s.DeleteRole(ctx, super) }},
		{"assign to a user", func() error { _, err := s.SetUserRoles(ctx, userUUIDs[userB], []uuid.UUID{super}); return err }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.call(); !errors.Is(err, domain.ErrSystemRole) {
				t.Errorf("%s super_admin error = %v, want ErrSystemRole", tt.name, err)
			}
		})
	}
}

func TestAccessService_PreventsPrivilegeEscalation(t *testing.T) {
	// newSetup gives manager users:read and users:delete, and an actor allowed to manage roles who
	// holds users:read but not users:delete.
	newSetup := func() (*AccessService, *fakeRepository, context.Context, uuid.UUID) {
		s, repo, _ := newTestService()
		repo.grants[managerRoleID] = []string{usersRead, usersDelete}
		weak := asActor(repo, domain.RolesCreate, domain.RolesUpdate, domain.RolesDelete, domain.RolesAssign, usersRead)

		return s, repo, weak, repo.roles[1].UUID
	}

	t.Run("create a role with an unheld permission", func(t *testing.T) {
		s, _, weak, _ := newSetup()

		_, err := s.CreateRole(weak, domain.CreateRoleInput{Code: "x", Name: "X", Permissions: []string{usersDelete}})

		if !errors.Is(err, domain.ErrEscalation) {
			t.Errorf("CreateRole() error = %v, want ErrEscalation", err)
		}
	})

	t.Run("add an unheld permission to a role", func(t *testing.T) {
		s, _, weak, manager := newSetup()

		_, err := s.ReplaceRolePermissions(weak, manager, []string{usersRead, usersDelete, usersUpdate})

		if !errors.Is(err, domain.ErrEscalation) {
			t.Errorf("ReplaceRolePermissions() error = %v, want ErrEscalation", err)
		}
	})

	t.Run("delete a role holding an unheld permission", func(t *testing.T) {
		s, _, weak, manager := newSetup()

		if err := s.DeleteRole(weak, manager); !errors.Is(err, domain.ErrEscalation) {
			t.Errorf("DeleteRole() error = %v, want ErrEscalation", err)
		}
	})

	t.Run("rename a role holding an unheld permission", func(t *testing.T) {
		s, _, weak, manager := newSetup()

		if _, err := s.RenameRole(weak, manager, "Boss"); !errors.Is(err, domain.ErrEscalation) {
			t.Errorf("RenameRole() error = %v, want ErrEscalation", err)
		}
	})

	t.Run("assign a role holding an unheld permission", func(t *testing.T) {
		s, _, weak, manager := newSetup()

		if _, err := s.SetUserRoles(weak, userUUIDs[userB], []uuid.UUID{manager}); !errors.Is(err, domain.ErrEscalation) {
			t.Errorf("SetUserRoles() error = %v, want ErrEscalation", err)
		}
	})

	// userC holds users:delete through manager, so the actor may not touch their roles at all.
	t.Run("remove every role from a user holding an unheld permission", func(t *testing.T) {
		s, repo, weak, _ := newSetup()
		repo.userRoles[userC] = []int64{managerRoleID}

		if _, err := s.SetUserRoles(weak, userUUIDs[userC], nil); !errors.Is(err, actor.ErrCannotManageStrongerUser) {
			t.Errorf("SetUserRoles() error = %v, want ErrCannotManageStrongerUser", err)
		}
	})

	t.Run("add a fully held role to a user holding an unheld permission", func(t *testing.T) {
		s, repo, weak, manager := newSetup()
		repo.userRoles[userC] = []int64{managerRoleID}
		held, err := repo.CreateRole(context.Background(), "held", "Held")
		if err != nil {
			t.Fatalf("setup: CreateRole() error = %v", err)
		}

		repo.grants[held.ID] = []string{usersRead}

		if _, err := s.SetUserRoles(weak, userUUIDs[userC], []uuid.UUID{manager, held.UUID}); !errors.Is(err, actor.ErrCannotManageStrongerUser) {
			t.Errorf("SetUserRoles() error = %v, want ErrCannotManageStrongerUser", err)
		}
	})

	// Removing a permission the actor lacks is taking away access they could not grant.
	t.Run("remove an unheld permission from a role", func(t *testing.T) {
		s, _, weak, manager := newSetup()

		if _, err := s.ReplaceRolePermissions(weak, manager, []string{usersRead}); !errors.Is(err, domain.ErrEscalation) {
			t.Errorf("ReplaceRolePermissions() error = %v, want ErrEscalation", err)
		}
	})

	// Only what changes is checked: users:delete stays, so the actor may add users:read beside it.
	t.Run("add a held permission beside an unheld one that stays", func(t *testing.T) {
		s, repo, weak, manager := newSetup()
		repo.grants[managerRoleID] = []string{usersDelete}

		if _, err := s.ReplaceRolePermissions(weak, manager, []string{usersRead, usersDelete}); err != nil {
			t.Errorf("ReplaceRolePermissions() error = %v, want nil", err)
		}
	})
}

func TestAccessService_ReloadsActorPermissionsBeforeChanges(t *testing.T) {
	// The request's cached copy still holds roles:update and roles:delete; the database no longer does.
	newSetup := func() (*AccessService, context.Context, uuid.UUID) {
		s, repo, _ := newTestService()
		ctx := asActor(repo, domain.RolesUpdate, domain.RolesDelete, usersRead)
		repo.actorPerms[actorID] = []string{usersRead}

		return s, ctx, repo.roles[1].UUID
	}

	t.Run("replace permissions", func(t *testing.T) {
		s, ctx, manager := newSetup()

		if _, err := s.ReplaceRolePermissions(ctx, manager, []string{usersRead}); !errors.Is(err, actor.ErrForbidden) {
			t.Errorf("ReplaceRolePermissions() error = %v, want actor.ErrForbidden", err)
		}
	})

	t.Run("delete role", func(t *testing.T) {
		s, ctx, manager := newSetup()

		if err := s.DeleteRole(ctx, manager); !errors.Is(err, actor.ErrForbidden) {
			t.Errorf("DeleteRole() error = %v, want actor.ErrForbidden", err)
		}
	})
}

func TestAccessService_ReturnsRepositoryErrors(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name   string
		failOn string
		call   func(s *AccessService, repo *fakeRepository) error
	}{
		{"check permissions", "ListPermissions", func(s *AccessService, _ *fakeRepository) error {
			return s.CheckPermissions(ctx)
		}},
		{"list permission groups", "ListPermissions", func(s *AccessService, _ *fakeRepository) error {
			_, err := s.ListPermissionGroups(ctx)
			return err
		}},
		{"create role with permissions", "ListPermissions", func(s *AccessService, repo *fakeRepository) error {
			_, err := s.CreateRole(asActor(repo, allPermissions...), domain.CreateRoleInput{Code: "x", Name: "X", Permissions: []string{usersRead}})
			return err
		}},
		{"get role", "ListRoles", func(s *AccessService, repo *fakeRepository) error {
			_, err := s.GetRole(ctx, repo.roles[1].UUID)
			return err
		}},
		{"list roles", "ListRoles", func(s *AccessService, _ *fakeRepository) error {
			_, err := s.ListRoles(ctx)
			return err
		}},
		{"rename role while locking it", "LockRoles", func(s *AccessService, repo *fakeRepository) error {
			_, err := s.RenameRole(asActor(repo, domain.RolesUpdate), repo.roles[1].UUID, "Boss")
			return err
		}},
		{"list user roles", "ListUserRoles", func(s *AccessService, _ *fakeRepository) error {
			_, err := s.ListUserRoles(ctx, userUUIDs[userA])
			return err
		}},
		{"set user roles while reading current roles", "ListUserRoles", func(s *AccessService, repo *fakeRepository) error {
			_, err := s.SetUserRoles(asActor(repo, domain.RolesAssign), userUUIDs[userA], nil)
			return err
		}},
		{"set user roles while locking roles", "LockRoles", func(s *AccessService, repo *fakeRepository) error {
			_, err := s.SetUserRoles(asActor(repo, domain.RolesAssign), userUUIDs[userA], []uuid.UUID{repo.roles[1].UUID})
			return err
		}},
		{"set user roles while reading wanted roles", "ListRoles", func(s *AccessService, repo *fakeRepository) error {
			_, err := s.SetUserRoles(asActor(repo, domain.RolesAssign), userUUIDs[userA], []uuid.UUID{repo.roles[1].UUID})
			return err
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, repo, _ := newTestService()
			repo.failing = []string{tt.failOn}

			if err := tt.call(s, repo); !errors.Is(err, errRepo) {
				t.Errorf("error = %v, want the %s error", err, tt.failOn)
			}
		})
	}
}
