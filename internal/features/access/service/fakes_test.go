package service

// =============================================================================
// TEST HELPERS (no test scenarios)
// =============================================================================
//
// File: fakes_test.go
// Purpose: Func-field fakes for AccessService (repository, user lookup, permission cache), the
//          roles and users the tests use, answer builders, and a constructor for the service.
// Used by: access_service_test.go
//
// =============================================================================

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/google/uuid"

	"jungo/internal/common/actor"
	"jungo/internal/features/access/domain"
)

// Another feature's permissions, standing in for the user feature's.
const (
	usersRead   = "users:read"
	usersUpdate = "users:update"
	usersDelete = "users:delete"
)

// allPermissions is the "permissions" Fx group the service receives: every code a feature uses.
var allPermissions = append([]string{usersRead, usersUpdate, usersDelete}, domain.Permissions...)

// actorID is the user every test acts as; targetID is the user whose roles they change.
const (
	actorID  int64 = 99
	targetID int64 = 10
)

// Fixed UUIDs, so a failure prints the same values on every run.
var (
	actorUUID      = uuid.MustParse("00000000-0000-0000-0000-000000000099")
	targetUUID     = uuid.MustParse("00000000-0000-0000-0000-000000000010")
	superAdminUUID = uuid.MustParse("00000000-0000-0000-0000-0000000000a1")
	managerUUID    = uuid.MustParse("00000000-0000-0000-0000-0000000000a2")
	extraUUID      = uuid.MustParse("00000000-0000-0000-0000-0000000000a3")
)

// errDB stands in for a failing database.
var errDB = errors.New("fake database: connection lost")

// superAdmin returns the system role granting perms; the API never changes or assigns it.
func superAdmin(perms ...string) *domain.Role {
	return &domain.Role{ID: 1, UUID: superAdminUUID, Code: "super_admin", IsSystem: true, Permissions: perms}
}

// manager returns a non-system role granting perms.
func manager(perms ...string) *domain.Role {
	return &domain.Role{ID: 2, UUID: managerUUID, Code: "manager", Name: "Manager", Permissions: perms}
}

// extra returns a second non-system role granting perms.
func extra(perms ...string) *domain.Role {
	return &domain.Role{ID: 3, UUID: extraUUID, Code: "extra", Name: "Extra", Permissions: perms}
}

// fakeRepository is a domain.AccessRepository and domain.UserLookup whose answers each test sets
// through the Func fields. Calling a method whose Func is nil panics, except LockRoles, which
// succeeds: every write locks its roles first, and the lock decides nothing a test checks.
type fakeRepository struct {
	GetUserPermissionsFunc           func(ctx context.Context, userID int64) ([]string, error)
	GetActorAndTargetPermissionsFunc func(ctx context.Context, actorID, targetID int64) ([]string, []string, error)
	ListPermissionsFunc              func(ctx context.Context) ([]domain.Permission, error)

	CreateRoleFunc             func(ctx context.Context, code, name string) (*domain.Role, error)
	ListRolesFunc              func(ctx context.Context, uids []uuid.UUID, countUsers bool) ([]*domain.Role, error)
	LockRolesFunc              func(ctx context.Context, uids []uuid.UUID) error
	UpdateRoleNameFunc         func(ctx context.Context, roleID int64, name string) error
	DeleteRoleFunc             func(ctx context.Context, roleID int64) error
	ReplaceRolePermissionsFunc func(ctx context.Context, roleID int64, codes []string) error
	ListUserIDsByRoleFunc      func(ctx context.Context, roleID int64, limit int32) ([]int64, error)

	ListUserRolesFunc    func(ctx context.Context, userID int64) ([]*domain.Role, error)
	ReplaceUserRolesFunc func(ctx context.Context, userID int64, roleIDs []int64) error
	GetUserIDFunc        func(ctx context.Context, uid uuid.UUID) (int64, error)
	LockUserFunc         func(ctx context.Context, uid uuid.UUID) (int64, error)
}

// WithTransaction runs fn directly: the fake has nothing to commit or roll back.
func (r *fakeRepository) WithTransaction(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

// GetUserPermissions answers through GetUserPermissionsFunc.
func (r *fakeRepository) GetUserPermissions(ctx context.Context, userID int64) ([]string, error) {
	return r.GetUserPermissionsFunc(ctx, userID)
}

// GetActorAndTargetPermissions answers through GetActorAndTargetPermissionsFunc.
func (r *fakeRepository) GetActorAndTargetPermissions(
	ctx context.Context,
	actorID, targetID int64,
) ([]string, []string, error) {
	return r.GetActorAndTargetPermissionsFunc(ctx, actorID, targetID)
}

// ListPermissions answers through ListPermissionsFunc.
func (r *fakeRepository) ListPermissions(ctx context.Context) ([]domain.Permission, error) {
	return r.ListPermissionsFunc(ctx)
}

// CreateRole answers through CreateRoleFunc.
func (r *fakeRepository) CreateRole(ctx context.Context, code, name string) (*domain.Role, error) {
	return r.CreateRoleFunc(ctx, code, name)
}

// ListRoles answers through ListRolesFunc.
func (r *fakeRepository) ListRoles(ctx context.Context, uids []uuid.UUID, countUsers bool) ([]*domain.Role, error) {
	return r.ListRolesFunc(ctx, uids, countUsers)
}

// LockRoles answers through LockRolesFunc, or succeeds when it is nil.
func (r *fakeRepository) LockRoles(ctx context.Context, uids []uuid.UUID) error {
	if r.LockRolesFunc == nil {
		return nil
	}

	return r.LockRolesFunc(ctx, uids)
}

// UpdateRoleName answers through UpdateRoleNameFunc.
func (r *fakeRepository) UpdateRoleName(ctx context.Context, roleID int64, name string) error {
	return r.UpdateRoleNameFunc(ctx, roleID, name)
}

// DeleteRole answers through DeleteRoleFunc.
func (r *fakeRepository) DeleteRole(ctx context.Context, roleID int64) error {
	return r.DeleteRoleFunc(ctx, roleID)
}

// ReplaceRolePermissions answers through ReplaceRolePermissionsFunc.
func (r *fakeRepository) ReplaceRolePermissions(ctx context.Context, roleID int64, codes []string) error {
	return r.ReplaceRolePermissionsFunc(ctx, roleID, codes)
}

// ListUserIDsByRole answers through ListUserIDsByRoleFunc.
func (r *fakeRepository) ListUserIDsByRole(ctx context.Context, roleID int64, limit int32) ([]int64, error) {
	return r.ListUserIDsByRoleFunc(ctx, roleID, limit)
}

// ListUserRoles answers through ListUserRolesFunc.
func (r *fakeRepository) ListUserRoles(ctx context.Context, userID int64) ([]*domain.Role, error) {
	return r.ListUserRolesFunc(ctx, userID)
}

// ReplaceUserRoles answers through ReplaceUserRolesFunc.
func (r *fakeRepository) ReplaceUserRoles(ctx context.Context, userID int64, roleIDs []int64) error {
	return r.ReplaceUserRolesFunc(ctx, userID, roleIDs)
}

// GetUserID answers through GetUserIDFunc.
func (r *fakeRepository) GetUserID(ctx context.Context, uid uuid.UUID) (int64, error) {
	return r.GetUserIDFunc(ctx, uid)
}

// LockUser answers through LockUserFunc.
func (r *fakeRepository) LockUser(ctx context.Context, uid uuid.UUID) (int64, error) {
	return r.LockUserFunc(ctx, uid)
}

// fakeCache is a domain.PermissionCache that never caches: GetOrLoad always loads, unless loadErr
// is set. It records every invalidation.
type fakeCache struct {
	loadErr error

	// users are the user IDs invalidated one by one; all counts InvalidateAll calls.
	users []int64
	all   int
}

// GetOrLoad returns loadErr when set, else what load returns.
func (c *fakeCache) GetOrLoad(_ context.Context, _ int64, load func() ([]string, error)) ([]string, error) {
	if c.loadErr != nil {
		return nil, c.loadErr
	}

	return load()
}

// InvalidateUsers records ids.
func (c *fakeCache) InvalidateUsers(_ context.Context, ids ...int64) {
	c.users = append(c.users, ids...)
}

// InvalidateAll counts the call.
func (c *fakeCache) InvalidateAll(context.Context) {
	c.all++
}

// holds answers GetUserPermissions with codes: what the database grants the actor right now.
func holds(codes ...string) func(context.Context, int64) ([]string, error) {
	return func(context.Context, int64) ([]string, error) {
		return codes, nil
	}
}

// actorAndTargetHold answers GetActorAndTargetPermissions with the actor's and the target's codes.
func actorAndTargetHold(
	actorCodes, targetCodes []string,
) func(context.Context, int64, int64) ([]string, []string, error) {
	return func(context.Context, int64, int64) ([]string, []string, error) {
		return actorCodes, targetCodes, nil
	}
}

// permissionsInDB answers ListPermissions with codes, as after the migrations that insert them.
func permissionsInDB(codes ...string) func(context.Context) ([]domain.Permission, error) {
	return func(context.Context) ([]domain.Permission, error) {
		perms := make([]domain.Permission, len(codes))
		for i, code := range codes {
			perms[i] = domain.Permission{Code: code, Group: "group"}
		}

		return perms, nil
	}
}

// rolesTable answers ListRoles from roles: the ones whose UUID is asked for, or all of them when
// uids is nil, as the query does.
func rolesTable(roles ...*domain.Role) func(context.Context, []uuid.UUID, bool) ([]*domain.Role, error) {
	return func(_ context.Context, uids []uuid.UUID, _ bool) ([]*domain.Role, error) {
		if uids == nil {
			return roles, nil
		}

		var found []*domain.Role
		for _, r := range roles {
			if slices.Contains(uids, r.UUID) {
				found = append(found, r)
			}
		}

		return found, nil
	}
}

// asActor returns a context whose actor holds perms, as middleware.Guard sets it from the cached
// permissions. Before a change the service re-reads them from the repository (holds).
func asActor(perms ...string) context.Context {
	return actor.With(context.Background(), &actor.Actor{UserID: actorID, UserUUID: actorUUID, Permissions: perms})
}

// newTestService returns an AccessService built from p. A nil Users is the fake repository, a nil
// Cache a fresh fakeCache and nil Permissions allPermissions.
func newTestService(t *testing.T, p AccessServiceParams) *AccessService {
	t.Helper()

	if p.Users == nil {
		p.Users = p.Repo.(*fakeRepository)
	}

	if p.Cache == nil {
		p.Cache = &fakeCache{}
	}

	if p.Permissions == nil {
		p.Permissions = allPermissions
	}

	return NewAccessService(p)
}

// wantErr fails the test unless errors.Is(got, want).
func wantErr(t *testing.T, got, want error) {
	t.Helper()

	if !errors.Is(got, want) {
		t.Fatalf("error = %v, want %v", got, want)
	}
}
