package service

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/jun-develop/junkit/slicex"

	"jungo/internal/common/actor"
	"jungo/internal/features/access/domain"
)

// maxUsersToInvalidate caps per-user cache invalidation; a role with more users invalidates all.
const maxUsersToInvalidate = 1000

// roleCodePattern matches roles.code (chk_roles_code_format).
var roleCodePattern = regexp.MustCompile(`^[a-z_]+$`)

// AccessService implements domain.AccessService and middleware.PermissionLoader.
type AccessService struct {
	repo   domain.AccessRepository
	users  domain.UserLookup
	cache  domain.PermissionCache
	logger *zap.Logger

	// permissions holds every code the features use (the "permissions" Fx group).
	permissions []string
}

// NewAccessService creates an AccessService; permissions are the codes every feature uses.
func NewAccessService(repo domain.AccessRepository, users domain.UserLookup, cache domain.PermissionCache, logger *zap.Logger, permissions []string) *AccessService {
	return &AccessService{repo: repo, users: users, cache: cache, logger: logger, permissions: permissions}
}

// Permissions returns the permission codes granted to a user through their roles.
func (s *AccessService) Permissions(ctx context.Context, userID int64) ([]string, error) {
	return s.cache.GetOrLoad(ctx, userID, func() ([]string, error) {
		return s.repo.GetUserPermissions(ctx, userID)
	})
}

// IsPermission reports whether code is one a feature uses.
func (s *AccessService) IsPermission(code string) bool {
	return slices.Contains(s.permissions, code)
}

// CheckPermissions returns an error when a permission a feature uses is missing from the
// permissions table (seeders/002_access.sql, or the feature's migration, has not run). It only reads.
func (s *AccessService) CheckPermissions(ctx context.Context) error {
	known, err := s.knownPermissions(ctx)
	if err != nil {
		return err
	}

	var missing []string
	for _, code := range s.permissions {
		if !known[code] {
			missing = append(missing, code)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("permissions used by the code are missing from the database (run seeders/002_access.sql, or make migrate-up for a feature's): %s", strings.Join(missing, ", "))
	}

	return nil
}

// ListPermissionGroups returns every permission in the database, grouped for the UI.
func (s *AccessService) ListPermissionGroups(ctx context.Context) ([]domain.PermissionGroup, error) {
	perms, err := s.repo.ListPermissions(ctx)
	if err != nil {
		return nil, err
	}

	return domain.GroupPermissions(perms), nil
}

// CreateRole creates a non-system role with optional permissions; the actor must hold all of them.
//
// Flow: validate -> check escalation + create + grant (tx) -> reload
func (s *AccessService) CreateRole(ctx context.Context, input domain.CreateRoleInput) (*domain.Role, error) {
	if !roleCodePattern.MatchString(input.Code) {
		return nil, domain.ErrInvalidRoleCode
	}

	if strings.TrimSpace(input.Name) == "" {
		return nil, domain.ErrInvalidRoleName
	}

	codes, err := s.normalizePermissions(ctx, input.Permissions)
	if err != nil {
		return nil, err
	}

	var role *domain.Role
	err = s.repo.WithTransaction(ctx, func(ctx context.Context) error {
		if err := s.checkGrant(ctx, domain.RolesCreate, codes); err != nil {
			return err
		}

		var err error
		if role, err = s.repo.CreateRole(ctx, input.Code, input.Name); err != nil || len(codes) == 0 {
			return err
		}

		return s.repo.ReplaceRolePermissions(ctx, role.ID, codes)
	})
	if err != nil {
		return nil, err
	}

	return s.GetRole(ctx, role.UUID)
}

// GetRole returns a role with its permissions and user count.
func (s *AccessService) GetRole(ctx context.Context, uid uuid.UUID) (*domain.Role, error) {
	roles, err := s.repo.ListRoles(ctx, []uuid.UUID{uid})
	if err != nil {
		return nil, err
	}

	if len(roles) == 0 {
		return nil, domain.ErrRoleNotFound
	}

	return roles[0], nil
}

// ListRoles returns every role with its permissions and user count.
func (s *AccessService) ListRoles(ctx context.Context) ([]*domain.Role, error) {
	return s.repo.ListRoles(ctx, nil)
}

// RenameRole changes a non-system role's display name; its code never changes. The actor must hold
// all its permissions, as for any other change to the role.
func (s *AccessService) RenameRole(ctx context.Context, uid uuid.UUID, name string) (*domain.Role, error) {
	if strings.TrimSpace(name) == "" {
		return nil, domain.ErrInvalidRoleName
	}

	err := s.repo.WithTransaction(ctx, func(ctx context.Context) error {
		role, err := s.lockMutableRole(ctx, uid)
		if err != nil {
			return err
		}

		if err := s.checkGrant(ctx, domain.RolesUpdate, role.Permissions); err != nil {
			return err
		}

		return s.repo.UpdateRoleName(ctx, role.ID, name)
	})
	if err != nil {
		return nil, err
	}

	return s.GetRole(ctx, uid)
}

// ReplaceRolePermissions replaces every permission of a non-system role. The actor must hold every
// permission added or removed, so they can neither grant nor take away access they lack; the
// permissions that stay are not checked.
//
// Flow: validate -> lock role + check escalation + replace (tx) -> invalidate its users -> reload
func (s *AccessService) ReplaceRolePermissions(ctx context.Context, uid uuid.UUID, codes []string) (*domain.Role, error) {
	codes, err := s.normalizePermissions(ctx, codes)
	if err != nil {
		return nil, err
	}

	var userIDs []int64
	err = s.repo.WithTransaction(ctx, func(ctx context.Context) error {
		role, err := s.lockMutableRole(ctx, uid)
		if err != nil {
			return err
		}

		if err := s.checkGrant(ctx, domain.RolesUpdate, changedPermissions(role.Permissions, codes)); err != nil {
			return err
		}

		if err := s.repo.ReplaceRolePermissions(ctx, role.ID, codes); err != nil {
			return err
		}

		userIDs, err = s.repo.ListUserIDsByRole(ctx, role.ID)

		return err
	})
	if err != nil {
		return nil, err
	}

	s.invalidateUsers(ctx, userIDs)

	return s.GetRole(ctx, uid)
}

// DeleteRole deletes a non-system role; its users lose it. The actor must hold all its permissions.
//
// Flow: lock role + check escalation + list users + delete (tx) -> invalidate users
func (s *AccessService) DeleteRole(ctx context.Context, uid uuid.UUID) error {
	var userIDs []int64
	err := s.repo.WithTransaction(ctx, func(ctx context.Context) error {
		role, err := s.lockMutableRole(ctx, uid)
		if err != nil {
			return err
		}

		if err := s.checkGrant(ctx, domain.RolesDelete, role.Permissions); err != nil {
			return err
		}

		if userIDs, err = s.repo.ListUserIDsByRole(ctx, role.ID); err != nil {
			return err
		}

		return s.repo.DeleteRole(ctx, role.ID)
	})
	if err != nil {
		return err
	}

	s.invalidateUsers(ctx, userIDs)

	return nil
}

// ListUserRoles returns the roles of the user uid.
func (s *AccessService) ListUserRoles(ctx context.Context, userUUID uuid.UUID) ([]*domain.Role, error) {
	userID, err := s.users.GetUserID(ctx, userUUID)
	if err != nil {
		return nil, err
	}

	return s.repo.ListUserRoles(ctx, userID)
}

// SetUserRoles replaces the user's non-system roles with roleUUIDs and returns the user's roles;
// system roles are kept and cannot be given. No one changes their own roles or those of a user
// holding a permission they lack, and the actor must hold every permission of each role added or
// removed, so assigning roles never grants more than the actor has.
//
// Flow: lock user + their roles -> diff -> check target and escalation -> replace (tx) -> invalidate user
func (s *AccessService) SetUserRoles(ctx context.Context, userUUID uuid.UUID, roleUUIDs []uuid.UUID) ([]*domain.Role, error) {
	if a, ok := actor.From(ctx); ok && a.Is(userUUID) {
		return nil, domain.ErrCannotChangeOwnRoles
	}

	var userID int64
	err := s.repo.WithTransaction(ctx, func(ctx context.Context) error {
		var err error
		if userID, err = s.users.LockUser(ctx, userUUID); err != nil {
			return err
		}

		current, err := s.repo.ListUserRoles(ctx, userID)
		if err != nil {
			return err
		}

		// Lock every role the change touches before reading their permissions.
		touched := slices.Clone(roleUUIDs)
		for _, r := range current {
			touched = append(touched, r.UUID)
		}

		if err := s.repo.LockRoles(ctx, touched); err != nil {
			return err
		}

		wanted, err := s.rolesByUUID(ctx, roleUUIDs)
		if err != nil {
			return err
		}

		var changed []uuid.UUID
		for _, r := range wanted {
			if r.IsSystem {
				return domain.ErrSystemRole
			}

			if !containsRole(current, r.UUID) {
				changed = append(changed, r.UUID)
			}
		}

		for _, r := range current {
			if !r.IsSystem && !containsRole(wanted, r.UUID) {
				changed = append(changed, r.UUID)
			}
		}

		changedRoles, err := s.rolesByUUID(ctx, changed)
		if err != nil {
			return err
		}

		var codes []string
		for _, r := range changedRoles {
			codes = append(codes, r.Permissions...)
		}

		held, err := actor.Reload(ctx, s.repo, domain.RolesAssign)
		if err != nil {
			return err
		}

		// As in UpdateUser, no one manages a stronger user: the actor holds all the user holds.
		target, err := s.repo.GetUserPermissions(ctx, userID)
		if err != nil {
			return err
		}

		if !actor.Covers(held, target) {
			return domain.ErrCannotManageStrongerUser
		}

		if !actor.Covers(held, codes) {
			return domain.ErrEscalation
		}

		ids := slicex.Map(wanted, func(r *domain.Role) int64 { return r.ID })

		return s.repo.ReplaceUserRoles(ctx, userID, ids)
	})
	if err != nil {
		return nil, err
	}

	s.cache.InvalidateUsers(ctx, userID)

	return s.repo.ListUserRoles(ctx, userID)
}

// lockMutableRole locks the role uid until the transaction in ctx ends, then returns it unless it
// is a system role (those are never changed through the API).
func (s *AccessService) lockMutableRole(ctx context.Context, uid uuid.UUID) (*domain.Role, error) {
	if err := s.repo.LockRoles(ctx, []uuid.UUID{uid}); err != nil {
		return nil, err
	}

	role, err := s.GetRole(ctx, uid)
	if err != nil {
		return nil, err
	}

	if role.IsSystem {
		return nil, domain.ErrSystemRole
	}

	return role, nil
}

// checkGrant returns ErrEscalation when the actor lacks one of codes. The actor's permissions are
// read from the database, not the request's cached copy: a permission removed moments ago, even
// permission itself, no longer counts.
func (s *AccessService) checkGrant(ctx context.Context, permission string, codes []string) error {
	held, err := actor.Reload(ctx, s.repo, permission)
	if err != nil {
		return err
	}

	if !actor.Covers(held, codes) {
		return domain.ErrEscalation
	}

	return nil
}

// invalidateUsers drops the cached permissions of userIDs, or of everyone past maxUsersToInvalidate.
func (s *AccessService) invalidateUsers(ctx context.Context, userIDs []int64) {
	if len(userIDs) > maxUsersToInvalidate {
		s.cache.InvalidateAll(ctx)
		return
	}

	s.cache.InvalidateUsers(ctx, userIDs...)
}

// rolesByUUID returns the roles of uids (duplicates ignored), or ErrRoleNotFound if one is missing.
func (s *AccessService) rolesByUUID(ctx context.Context, uids []uuid.UUID) ([]*domain.Role, error) {
	uids = slices.Compact(slices.SortedFunc(slices.Values(uids), func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) }))
	if len(uids) == 0 {
		// Never call ListRoles with nil here: nil lists every role.
		return nil, nil
	}

	roles, err := s.repo.ListRoles(ctx, uids)
	if err != nil {
		return nil, err
	}

	if len(roles) != len(uids) {
		return nil, domain.ErrRoleNotFound
	}

	return roles, nil
}

// containsRole reports whether roles has the role uid.
func containsRole(roles []*domain.Role, uid uuid.UUID) bool {
	return slices.ContainsFunc(roles, func(r *domain.Role) bool { return r.UUID == uid })
}

// changedPermissions returns the codes in exactly one of before and after.
func changedPermissions(before, after []string) []string {
	var changed []string
	for _, code := range after {
		if !slices.Contains(before, code) {
			changed = append(changed, code)
		}
	}

	for _, code := range before {
		if !slices.Contains(after, code) {
			changed = append(changed, code)
		}
	}

	return changed
}

// normalizePermissions checks codes exist in the permissions table and returns them sorted,
// without duplicates.
func (s *AccessService) normalizePermissions(ctx context.Context, codes []string) ([]string, error) {
	if len(codes) == 0 {
		return nil, nil
	}

	known, err := s.knownPermissions(ctx)
	if err != nil {
		return nil, err
	}

	for _, code := range codes {
		if !known[code] {
			return nil, domain.ErrUnknownPermission
		}
	}

	return slices.Compact(slices.Sorted(slices.Values(codes))), nil
}

// knownPermissions returns the set of permission codes in the database.
func (s *AccessService) knownPermissions(ctx context.Context) (map[string]bool, error) {
	perms, err := s.repo.ListPermissions(ctx)
	if err != nil {
		return nil, err
	}

	known := make(map[string]bool, len(perms))
	for _, p := range perms {
		known[p.Code] = true
	}

	return known, nil
}
