package service

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"go.uber.org/zap"

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

// fakeRepository is an in-memory AccessRepository and UserLookup mirroring the SQL.
type fakeRepository struct {
	permissions map[string]string // code -> group
	roles       []*domain.Role
	grants      map[int64][]string // role ID -> codes
	userRoles   map[int64][]int64  // user ID -> role IDs
	actorPerms  map[int64][]string // user ID -> codes, for actors that hold no role here
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
			{ID: 1, UUID: uuid.New(), Code: "super_admin", IsSystem: true},
			{ID: 2, UUID: uuid.New(), Code: "manager"},
		},
		grants:     map[int64][]string{},
		userRoles:  map[int64][]int64{},
		actorPerms: map[int64][]string{},
	}
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

func (r *fakeRepository) ListPermissions(context.Context) ([]domain.Permission, error) {
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

func (r *fakeRepository) ListRoles(_ context.Context, uuids []uuid.UUID) ([]*domain.Role, error) {
	var out []*domain.Role
	for _, role := range r.roles {
		if uuids != nil && !slices.Contains(uuids, role.UUID) {
			continue
		}

		full := *role
		full.Permissions = slices.Sorted(slices.Values(r.grants[role.ID]))
		ids, _ := r.ListUserIDsByRole(context.Background(), role.ID)
		full.UserCount = int64(len(ids))
		out = append(out, &full)
	}

	return out, nil
}

func (r *fakeRepository) LockRoles(context.Context, []uuid.UUID) error { return nil }

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

// userUUIDs maps the fake users' IDs to their UUIDs.
var userUUIDs = map[int64]uuid.UUID{10: uuid.New(), 20: uuid.New(), 30: uuid.New()}

func (r *fakeRepository) ReplaceRolePermissions(_ context.Context, roleID int64, codes []string) error {
	r.grants[roleID] = slices.Clone(codes)
	return nil
}

func (r *fakeRepository) ListUserIDsByRole(_ context.Context, roleID int64) ([]int64, error) {
	var ids []int64
	for userID, roles := range r.userRoles {
		if slices.Contains(roles, roleID) {
			ids = append(ids, userID)
		}
	}

	return ids, nil
}

// fakeCache records invalidations and never caches.
type fakeCache struct {
	users []int64
	all   int
}

func (c *fakeCache) GetOrLoad(_ context.Context, _ int64, load func() ([]string, error)) ([]string, error) {
	return load()
}

func (c *fakeCache) InvalidateUsers(_ context.Context, ids ...int64) {
	c.users = append(c.users, ids...)
}

func (c *fakeCache) InvalidateAll(context.Context) { c.all++ }

func newTestService() (*AccessService, *fakeRepository, *fakeCache) {
	repo, c := newFakeRepository(), &fakeCache{}

	return NewAccessService(repo, repo, c, zap.NewNop(), allPermissions), repo, c
}

func TestCheckPermissions(t *testing.T) {
	ctx := context.Background()
	s, repo, _ := newTestService()

	if err := s.CheckPermissions(ctx); err != nil {
		t.Fatalf("all migrated: err = %v, want nil", err)
	}

	delete(repo.permissions, domain.RolesAssign)
	if err := s.CheckPermissions(ctx); err == nil || !strings.Contains(err.Error(), domain.RolesAssign) {
		t.Errorf("missing roles:assign: err = %v, want it named", err)
	}
}

func TestPermissionsComeFromTheDatabase(t *testing.T) {
	s, repo, _ := newTestService()
	manager := repo.roles[1].UUID

	// A permission the database has before the code uses it can already be granted...
	repo.permissions["reports:read"] = "reports"
	if _, err := s.ReplaceRolePermissions(asActor(repo, domain.RolesUpdate, "reports:read"), manager, []string{"reports:read"}); err != nil {
		t.Errorf("grant seeded permission: err = %v, want nil", err)
	}

	// ...and one missing from the database cannot, even if the code names it.
	delete(repo.permissions, usersDelete)
	if _, err := s.ReplaceRolePermissions(asActor(repo, allPermissions...), manager, []string{usersDelete}); !errors.Is(err, domain.ErrUnknownPermission) {
		t.Errorf("grant unseeded permission: err = %v, want ErrUnknownPermission", err)
	}
}

func TestReplaceRolePermissions(t *testing.T) {
	s, repo, c := newTestService()
	ctx := asActor(repo, allPermissions...)
	repo.userRoles[20] = []int64{2}
	manager, super := repo.roles[1].UUID, repo.roles[0].UUID

	if _, err := s.ReplaceRolePermissions(ctx, manager, []string{usersUpdate, usersRead, usersRead}); err != nil {
		t.Fatal(err)
	}

	if want := []string{usersRead, usersUpdate}; !slices.Equal(repo.grants[2], want) {
		t.Errorf("grants = %v, want %v", repo.grants[2], want)
	}

	if !slices.Equal(c.users, []int64{20}) {
		t.Errorf("invalidated users = %v, want [20]", c.users)
	}

	cases := []struct {
		name  string
		role  uuid.UUID
		codes []string
		want  error
	}{
		{"typo", manager, []string{"users:typo"}, domain.ErrUnknownPermission},
		{"system role", super, []string{usersRead}, domain.ErrSystemRole},
		{"missing role", uuid.New(), []string{usersRead}, domain.ErrRoleNotFound},
	}
	for _, tc := range cases {
		if _, err := s.ReplaceRolePermissions(ctx, tc.role, tc.codes); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestCreateRole(t *testing.T) {
	s, repo, _ := newTestService()
	ctx := asActor(repo, allPermissions...)

	for _, code := range []string{"", "Manager", "sales-team", "a1"} {
		if _, err := s.CreateRole(ctx, domain.CreateRoleInput{Code: code, Name: "Name"}); !errors.Is(err, domain.ErrInvalidRoleCode) {
			t.Errorf("CreateRole(%q) = %v, want ErrInvalidRoleCode", code, err)
		}
	}

	role, err := s.CreateRole(ctx, domain.CreateRoleInput{Code: "sales_team", Name: "Sales", Permissions: []string{usersRead}})
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(role.Permissions, []string{usersRead}) {
		t.Errorf("permissions = %v, want [users:read]", role.Permissions)
	}

	if _, err := s.CreateRole(ctx, domain.CreateRoleInput{Code: "sales_team", Name: "Sales"}); !errors.Is(err, domain.ErrRoleAlreadyExists) {
		t.Errorf("duplicate = %v, want ErrRoleAlreadyExists", err)
	}

	if _, err := s.CreateRole(ctx, domain.CreateRoleInput{Code: "blank_name", Name: "  "}); !errors.Is(err, domain.ErrInvalidRoleName) {
		t.Errorf("blank name = %v, want ErrInvalidRoleName", err)
	}

	// Without an actor (not behind a guarded route) creating fails closed.
	if _, err := s.CreateRole(context.Background(), domain.CreateRoleInput{Code: "no_actor", Name: "X", Permissions: []string{usersRead}}); !errors.Is(err, actor.ErrForbidden) {
		t.Errorf("no actor: err = %v, want actor.ErrForbidden", err)
	}
}

// asActor returns a context whose actor holds perms, as middleware.Guard sets it, and holds them in
// repo too (the service reloads them from the database before a change).
func asActor(repo *fakeRepository, perms ...string) context.Context {
	repo.actorPerms[99] = perms
	return actor.With(context.Background(), &actor.Actor{UserID: 99, UserUUID: uuid.New(), Permissions: perms})
}

func TestRoleAPI_SystemRoleIsImmutable(t *testing.T) {
	s, repo, _ := newTestService()
	ctx := asActor(repo, domain.RolesUpdate, domain.RolesDelete, domain.RolesAssign, usersRead)
	super := repo.roles[0].UUID

	if _, err := s.RenameRole(ctx, super, "Boss"); !errors.Is(err, domain.ErrSystemRole) {
		t.Errorf("rename = %v, want ErrSystemRole", err)
	}

	if _, err := s.ReplaceRolePermissions(ctx, super, nil); !errors.Is(err, domain.ErrSystemRole) {
		t.Errorf("replace permissions = %v, want ErrSystemRole", err)
	}

	if err := s.DeleteRole(ctx, super); !errors.Is(err, domain.ErrSystemRole) {
		t.Errorf("delete = %v, want ErrSystemRole", err)
	}

	if _, err := s.SetUserRoles(ctx, userUUIDs[20], []uuid.UUID{super}); !errors.Is(err, domain.ErrSystemRole) {
		t.Errorf("assign super_admin = %v, want ErrSystemRole", err)
	}
}

func TestRoleAPI_NoEscalation(t *testing.T) {
	s, repo, _ := newTestService()
	repo.grants[2] = []string{usersRead, usersDelete}
	manager := repo.roles[1].UUID
	weak := asActor(repo, domain.RolesCreate, domain.RolesUpdate, domain.RolesDelete, domain.RolesAssign, usersRead)

	if _, err := s.CreateRole(weak, domain.CreateRoleInput{Code: "x", Name: "X", Permissions: []string{usersDelete}}); !errors.Is(err, domain.ErrEscalation) {
		t.Errorf("create with unheld permission = %v, want ErrEscalation", err)
	}

	if _, err := s.ReplaceRolePermissions(weak, manager, []string{usersRead, usersDelete, usersUpdate}); !errors.Is(err, domain.ErrEscalation) {
		t.Errorf("grant unheld permission = %v, want ErrEscalation", err)
	}

	if err := s.DeleteRole(weak, manager); !errors.Is(err, domain.ErrEscalation) {
		t.Errorf("delete stronger role = %v, want ErrEscalation", err)
	}

	if _, err := s.RenameRole(weak, manager, "Boss"); !errors.Is(err, domain.ErrEscalation) {
		t.Errorf("rename stronger role = %v, want ErrEscalation", err)
	}

	if _, err := s.SetUserRoles(weak, userUUIDs[20], []uuid.UUID{manager}); !errors.Is(err, domain.ErrEscalation) {
		t.Errorf("assign stronger role = %v, want ErrEscalation", err)
	}

	// The user holds users:delete through manager, so the weak actor may not touch their roles at all,
	// not even to add one it fully holds.
	repo.userRoles[30] = []int64{2}
	if _, err := s.SetUserRoles(weak, userUUIDs[30], nil); !errors.Is(err, domain.ErrCannotManageStrongerUser) {
		t.Errorf("remove role from stronger user = %v, want ErrCannotManageStrongerUser", err)
	}

	held, _ := repo.CreateRole(context.Background(), "held", "Held")
	repo.grants[held.ID] = []string{usersRead}
	if _, err := s.SetUserRoles(weak, userUUIDs[30], []uuid.UUID{manager, held.UUID}); !errors.Is(err, domain.ErrCannotManageStrongerUser) {
		t.Errorf("add held role to stronger user = %v, want ErrCannotManageStrongerUser", err)
	}

	// Removing a permission the actor lacks is taking away access they could not grant.
	if _, err := s.ReplaceRolePermissions(weak, manager, []string{usersRead}); !errors.Is(err, domain.ErrEscalation) {
		t.Errorf("remove unheld permission = %v, want ErrEscalation", err)
	}

	// Only what changes is checked: users:delete stays, so the actor may change users:read around it.
	repo.grants[2] = []string{usersDelete}
	if _, err := s.ReplaceRolePermissions(weak, manager, []string{usersRead, usersDelete}); err != nil {
		t.Errorf("add held permission beside an unheld one = %v, want nil", err)
	}
}

func TestSetUserRoles_NotOnSelf(t *testing.T) {
	s, repo, _ := newTestService()
	repo.actorPerms[10] = []string{domain.RolesAssign, usersRead}
	self := actor.With(context.Background(), &actor.Actor{UserID: 10, UserUUID: userUUIDs[10], Permissions: repo.actorPerms[10]})

	if _, err := s.SetUserRoles(self, userUUIDs[10], []uuid.UUID{repo.roles[1].UUID}); !errors.Is(err, domain.ErrCannotChangeOwnRoles) {
		t.Errorf("own roles = %v, want ErrCannotChangeOwnRoles", err)
	}
}

func TestSetUserRoles(t *testing.T) {
	s, repo, c := newTestService()
	repo.grants[2] = []string{usersRead}
	extra, _ := repo.CreateRole(context.Background(), "extra", "Extra")
	repo.userRoles[10] = []int64{1} // super_admin
	ctx := asActor(repo, domain.RolesAssign, usersRead)

	roles, err := s.SetUserRoles(ctx, userUUIDs[10], []uuid.UUID{repo.roles[1].UUID, extra.UUID, extra.UUID})
	if err != nil {
		t.Fatal(err)
	}

	codes := make([]string, len(roles))
	for i, r := range roles {
		codes[i] = r.Code
	}

	if want := []string{"super_admin", "manager", "extra"}; !slices.Equal(codes, want) {
		t.Errorf("roles = %v, want %v (system role kept)", codes, want)
	}

	if !slices.Equal(c.users, []int64{10}) {
		t.Errorf("invalidated users = %v, want [10]", c.users)
	}

	if roles, _ := s.SetUserRoles(ctx, userUUIDs[10], []uuid.UUID{}); len(roles) != 1 || roles[0].Code != "super_admin" {
		t.Errorf("clearing roles kept %v, want only super_admin", roles)
	}

	if _, err := s.SetUserRoles(ctx, userUUIDs[10], []uuid.UUID{uuid.New()}); !errors.Is(err, domain.ErrRoleNotFound) {
		t.Errorf("unknown role = %v, want ErrRoleNotFound", err)
	}

	if _, err := s.SetUserRoles(ctx, uuid.New(), nil); !errors.Is(err, domain.ErrUserNotFound) {
		t.Errorf("unknown user = %v, want ErrUserNotFound", err)
	}
}

func TestDeleteRole_InvalidatesItsUsers(t *testing.T) {
	s, repo, c := newTestService()
	repo.userRoles[20] = []int64{2}

	if err := s.DeleteRole(asActor(repo, domain.RolesDelete), repo.roles[1].UUID); err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(c.users, []int64{20}) {
		t.Errorf("invalidated users = %v, want [20]", c.users)
	}

	if _, err := s.GetRole(context.Background(), uuid.New()); !errors.Is(err, domain.ErrRoleNotFound) {
		t.Errorf("get missing role = %v, want ErrRoleNotFound", err)
	}
}

func TestChangesReloadTheActorsPermissions(t *testing.T) {
	s, repo, _ := newTestService()
	manager := repo.roles[1].UUID

	// The request's cached copy still holds roles:update and roles:delete; the database no longer does.
	ctx := asActor(repo, domain.RolesUpdate, domain.RolesDelete, usersRead)
	repo.actorPerms[99] = []string{usersRead}

	if _, err := s.ReplaceRolePermissions(ctx, manager, []string{usersRead}); !errors.Is(err, actor.ErrForbidden) {
		t.Errorf("replace permissions = %v, want actor.ErrForbidden", err)
	}

	if err := s.DeleteRole(ctx, manager); !errors.Is(err, actor.ErrForbidden) {
		t.Errorf("delete = %v, want actor.ErrForbidden", err)
	}
}
