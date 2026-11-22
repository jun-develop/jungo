package service

// =============================================================================
// TEST HELPERS (no test scenarios)
// =============================================================================
//
// File: fakes_test.go
// Purpose: In-memory fakes for AccessService: a repository (AccessRepository + UserLookup)
//          mirroring the SQL, a permission cache that records invalidations, fixed users and
//          roles, and helpers to build a service and an acting user.
// Used by: access_service_test.go
//
// =============================================================================

import (
	"context"
	"errors"
	"slices"

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

// allPermissions is the "permissions" Fx group the tests' AccessService receives.
var allPermissions = append([]string{usersRead, usersUpdate, usersDelete}, domain.Permissions...)

// The fake users' IDs; actorID is the user asActor acts as.
const (
	userA   int64 = 10
	userB   int64 = 20
	userC   int64 = 30
	actorID int64 = 99
)

// The fake roles' IDs, in newFakeRepository's order.
const (
	superAdminRoleID int64 = 1
	managerRoleID    int64 = 2
)

// userUUIDs maps the fake users' IDs to their UUIDs.
var userUUIDs = map[int64]uuid.UUID{userA: uuid.New(), userB: uuid.New(), userC: uuid.New()}

// errRepo is the error a fake method returns when the test makes it fail.
var errRepo = errors.New("fake repository: connection lost")

// fakeRepository is an in-memory AccessRepository and UserLookup mirroring the SQL.
type fakeRepository struct {
	// permissions maps each code to its group.
	permissions map[string]string
	roles       []*domain.Role

	// grants maps a role ID to its codes; userRoles a user ID to their role IDs; actorPerms a user
	// ID to codes for actors that hold no role here.
	grants     map[int64][]string
	userRoles  map[int64][]int64
	actorPerms map[int64][]string

	// failing names the methods that return errRepo instead of answering.
	failing []string
}

// newFakeRepository returns a repository holding every permission in allPermissions, as after the
// migrations, plus super_admin and manager.
func newFakeRepository() *fakeRepository {
	perms := make(map[string]string, len(allPermissions))
	for _, code := range allPermissions {
		perms[code] = "group"
	}

	return &fakeRepository{
		permissions: perms,
		roles: []*domain.Role{
			{ID: superAdminRoleID, UUID: uuid.New(), Code: "super_admin", IsSystem: true},
			{ID: managerRoleID, UUID: uuid.New(), Code: "manager"},
		},
		grants:     map[int64][]string{},
		userRoles:  map[int64][]int64{},
		actorPerms: map[int64][]string{},
	}
}

// fails reports whether the test made method fail.
func (r *fakeRepository) fails(method string) bool {
	return slices.Contains(r.failing, method)
}

func (r *fakeRepository) WithTransaction(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

func (r *fakeRepository) GetUserPermissions(_ context.Context, userID int64) ([]string, error) {
	codes := slices.Clone(r.actorPerms[userID])
	for _, roleID := range r.userRoles[userID] {
		codes = append(codes, r.grants[roleID]...)
	}

	return slices.Compact(slices.Sorted(slices.Values(codes))), nil
}

func (r *fakeRepository) GetActorAndTargetPermissions(ctx context.Context, actorID, targetID int64) ([]string, []string, error) {
	held, _ := r.GetUserPermissions(ctx, actorID)
	target, _ := r.GetUserPermissions(ctx, targetID)

	return held, target, nil
}

func (r *fakeRepository) ListPermissions(context.Context) ([]domain.Permission, error) {
	if r.fails("ListPermissions") {
		return nil, errRepo
	}

	var perms []domain.Permission
	for code, group := range r.permissions {
		perms = append(perms, domain.Permission{Code: code, Group: group})
	}

	return perms, nil
}

func (r *fakeRepository) CreateRole(_ context.Context, code, name string) (*domain.Role, error) {
	if _, err := r.GetRoleByCode(context.Background(), code); err == nil {
		return nil, domain.ErrRoleAlreadyExists
	}

	role := &domain.Role{ID: int64(len(r.roles) + 1), UUID: uuid.New(), Code: code, Name: name}
	r.roles = append(r.roles, role)

	return role, nil
}

func (r *fakeRepository) GetRoleByCode(_ context.Context, code string) (*domain.Role, error) {
	for _, role := range r.roles {
		if role.Code == code {
			return role, nil
		}
	}

	return nil, domain.ErrRoleNotFound
}

func (r *fakeRepository) ListRoles(_ context.Context, uuids []uuid.UUID, countUsers bool) ([]*domain.Role, error) {
	if r.fails("ListRoles") {
		return nil, errRepo
	}

	var out []*domain.Role
	for _, role := range r.roles {
		if uuids != nil && !slices.Contains(uuids, role.UUID) {
			continue
		}

		full := *role
		full.Permissions = slices.Sorted(slices.Values(r.grants[role.ID]))
		if countUsers {
			ids, _ := r.ListUserIDsByRole(context.Background(), role.ID, 0)
			full.UserCount = int64(len(ids))
		}

		out = append(out, &full)
	}

	return out, nil
}

func (r *fakeRepository) LockRoles(context.Context, []uuid.UUID) error {
	if r.fails("LockRoles") {
		return errRepo
	}

	return nil
}

func (r *fakeRepository) UpdateRoleName(_ context.Context, roleID int64, name string) error {
	for _, role := range r.roles {
		if role.ID == roleID {
			role.Name = name
			return nil
		}
	}

	return domain.ErrRoleNotFound
}

func (r *fakeRepository) DeleteRole(_ context.Context, roleID int64) error {
	r.roles = slices.DeleteFunc(r.roles, func(role *domain.Role) bool { return role.ID == roleID && !role.IsSystem })
	delete(r.grants, roleID)
	for userID := range r.userRoles {
		r.userRoles[userID] = slices.DeleteFunc(r.userRoles[userID], func(id int64) bool { return id == roleID })
	}

	return nil
}

func (r *fakeRepository) LockUser(ctx context.Context, uid uuid.UUID) (int64, error) {
	return r.GetUserID(ctx, uid)
}

func (r *fakeRepository) GetUserID(_ context.Context, uid uuid.UUID) (int64, error) {
	for id, u := range userUUIDs {
		if u == uid {
			return id, nil
		}
	}

	return 0, domain.ErrUserNotFound
}

func (r *fakeRepository) ListUserRoles(_ context.Context, userID int64) ([]*domain.Role, error) {
	if r.fails("ListUserRoles") {
		return nil, errRepo
	}

	var out []*domain.Role
	for _, role := range r.roles {
		if slices.Contains(r.userRoles[userID], role.ID) {
			out = append(out, role)
		}
	}

	return out, nil
}

func (r *fakeRepository) ReplaceUserRoles(_ context.Context, userID int64, roleIDs []int64) error {
	keep := slices.DeleteFunc(slices.Clone(r.userRoles[userID]), func(id int64) bool { return !r.roles[id-1].IsSystem })
	r.userRoles[userID] = append(keep, roleIDs...)

	return nil
}

func (r *fakeRepository) ReplaceRolePermissions(_ context.Context, roleID int64, codes []string) error {
	r.grants[roleID] = slices.Clone(codes)
	return nil
}

// ListUserIDsByRole returns every user of the role when limit is 0.
func (r *fakeRepository) ListUserIDsByRole(_ context.Context, roleID int64, limit int32) ([]int64, error) {
	var ids []int64
	for userID, roles := range r.userRoles {
		if slices.Contains(roles, roleID) && (limit == 0 || len(ids) < int(limit)) {
			ids = append(ids, userID)
		}
	}

	return ids, nil
}

// fakeCache records invalidations and never caches; loadErr, when set, is returned instead of
// loading.
type fakeCache struct {
	users   []int64
	all     int
	loadErr error
}

func (c *fakeCache) GetOrLoad(_ context.Context, _ int64, load func() ([]string, error)) ([]string, error) {
	if c.loadErr != nil {
		return nil, c.loadErr
	}

	return load()
}

func (c *fakeCache) InvalidateUsers(_ context.Context, ids ...int64) {
	c.users = append(c.users, ids...)
}

func (c *fakeCache) InvalidateAll(context.Context) { c.all++ }

// asActor returns a context whose actor holds perms, as middleware.Guard sets it, and holds them in
// repo too (the service reloads them from the database before a change).
func asActor(repo *fakeRepository, perms ...string) context.Context {
	repo.actorPerms[actorID] = perms
	return actor.With(context.Background(), &actor.Actor{UserID: actorID, UserUUID: uuid.New(), Permissions: perms})
}

// newTestService returns an AccessService over a fresh fake repository and cache.
func newTestService() (*AccessService, *fakeRepository, *fakeCache) {
	repo, c := newFakeRepository(), &fakeCache{}

	return NewAccessService(AccessServiceParams{Repo: repo, Users: repo, Cache: c, Permissions: allPermissions}), repo, c
}

// roleCodes returns the codes of roles, in order.
func roleCodes(roles []*domain.Role) []string {
	codes := make([]string, len(roles))
	for i, r := range roles {
		codes[i] = r.Code
	}

	return codes
}
