package repository

import (
	"context"

	"github.com/google/uuid"

	"github.com/jun-develop/junkit/database"
	"github.com/jun-develop/junkit/slicex"

	"jungo/internal/database/primary"
	"jungo/internal/database/primary/sqlc"
	"jungo/internal/features/access/domain"
)

// AccessRepository implements domain.AccessRepository.
type AccessRepository struct {
	db *primary.DB
}

// NewAccessRepository creates an AccessRepository backed by db.
func NewAccessRepository(db *primary.DB) *AccessRepository {
	return &AccessRepository{db: db}
}

// WithTransaction implements domain.AccessRepository.
func (r *AccessRepository) WithTransaction(ctx context.Context, fn func(ctx context.Context) error) error {
	return r.db.WithTransaction(ctx, fn)
}

// GetUserPermissions implements domain.AccessRepository and actor.PermissionReader.
func (r *AccessRepository) GetUserPermissions(ctx context.Context, userID int64) ([]string, error) {
	codes, err := r.db.Queries(ctx).GetUserPermissions(ctx, userID)
	if err != nil {
		return nil, wrap("get user permissions", err)
	}

	return codes, nil
}

// GetActorAndTargetPermissions implements domain.AccessRepository and actor.TargetPermissionReader.
func (r *AccessRepository) GetActorAndTargetPermissions(ctx context.Context, actorID, targetID int64) (actor, target []string, err error) {
	row, err := r.db.Queries(ctx).GetActorAndTargetPermissions(ctx, sqlc.GetActorAndTargetPermissionsParams{
		ActorID:  actorID,
		TargetID: targetID,
	})
	if err != nil {
		return nil, nil, wrap("get actor and target permissions", err)
	}

	return row.ActorPermissions, row.TargetPermissions, nil
}

// ListPermissions implements domain.AccessRepository; ordered by group, then code.
func (r *AccessRepository) ListPermissions(ctx context.Context) ([]domain.Permission, error) {
	rows, err := r.db.Queries(ctx).ListPermissions(ctx)
	if err != nil {
		return nil, wrap("list permissions", err)
	}

	return slicex.Map(rows, func(row sqlc.ListPermissionsRow) domain.Permission {
		return domain.Permission{Code: row.Code, Group: row.GroupCode}
	}), nil
}

// CreateRole implements domain.AccessRepository.
func (r *AccessRepository) CreateRole(ctx context.Context, code, name string) (*domain.Role, error) {
	row, err := r.db.Queries(ctx).CreateRole(ctx, sqlc.CreateRoleParams{Code: code, Name: name})
	if err != nil {
		return nil, wrap("create role", database.Match(err, map[database.ErrorType]error{
			database.ErrorUniqueViolation: domain.ErrRoleAlreadyExists,
		}))
	}

	return mapRole(row), nil
}

// ListRoles implements domain.AccessRepository; each role carries its permissions.
func (r *AccessRepository) ListRoles(ctx context.Context, uuids []uuid.UUID, countUsers bool) ([]*domain.Role, error) {
	rows, err := r.db.Queries(ctx).ListRoles(ctx, sqlc.ListRolesParams{Uuids: uuids, CountUsers: countUsers})
	if err != nil {
		return nil, wrap("list roles", err)
	}

	items := make([]*domain.Role, len(rows))
	for i, row := range rows {
		items[i] = &domain.Role{
			ID:          row.ID,
			UUID:        row.UUID,
			Code:        row.Code,
			Name:        row.Name,
			IsSystem:    row.IsSystem,
			CreatedAt:   row.CreatedAt,
			UpdatedAt:   row.UpdatedAt,
			Permissions: row.Permissions,
			UserCount:   row.UserCount,
		}
	}

	return items, nil
}

// LockRoles implements domain.AccessRepository; it locks the roles' rows until the transaction in
// ctx ends, skipping missing roles.
func (r *AccessRepository) LockRoles(ctx context.Context, uuids []uuid.UUID) error {
	if err := r.db.Queries(ctx).LockRoles(ctx, uuids); err != nil {
		return wrap("lock roles", err)
	}

	return nil
}

// UpdateRoleName implements domain.AccessRepository.
func (r *AccessRepository) UpdateRoleName(ctx context.Context, roleID int64, name string) error {
	if _, err := r.db.Queries(ctx).UpdateRoleName(ctx, sqlc.UpdateRoleNameParams{ID: roleID, Name: name}); err != nil {
		return wrap("update role name", database.MatchNotFound(err, domain.ErrRoleNotFound))
	}

	return nil
}

// DeleteRole implements domain.AccessRepository; system roles are never deleted. Grants and
// assignments cascade.
func (r *AccessRepository) DeleteRole(ctx context.Context, roleID int64) error {
	n, err := r.db.Queries(ctx).DeleteRole(ctx, roleID)
	if err != nil {
		return wrap("delete role", err)
	}

	if n == 0 {
		return domain.ErrRoleNotFound
	}

	return nil
}

// ReplaceRolePermissions implements domain.AccessRepository; call it inside a transaction.
func (r *AccessRepository) ReplaceRolePermissions(ctx context.Context, roleID int64, codes []string) error {
	queries := r.db.Queries(ctx)
	if err := queries.DeleteRolePermissions(ctx, roleID); err != nil {
		return wrap("delete role permissions", err)
	}

	if err := queries.AddRolePermissions(ctx, sqlc.AddRolePermissionsParams{RoleID: roleID, Codes: codes}); err != nil {
		return wrap("add role permissions", err)
	}

	return nil
}

// ListUserIDsByRole implements domain.AccessRepository.
func (r *AccessRepository) ListUserIDsByRole(ctx context.Context, roleID int64, limit int32) ([]int64, error) {
	ids, err := r.db.Queries(ctx).ListUserIDsByRole(ctx, sqlc.ListUserIDsByRoleParams{RoleID: roleID, MaxRows: limit})
	if err != nil {
		return nil, wrap("list user ids by role", err)
	}

	return ids, nil
}

// ListUserRoles implements domain.AccessRepository; the roles carry no permissions or user count.
func (r *AccessRepository) ListUserRoles(ctx context.Context, userID int64) ([]*domain.Role, error) {
	rows, err := r.db.Queries(ctx).ListUserRoles(ctx, userID)
	if err != nil {
		return nil, wrap("list user roles", err)
	}

	return slicex.Map(rows, mapRole), nil
}

// ReplaceUserRoles implements domain.AccessRepository; it keeps the user's system roles. Call it
// inside a transaction.
func (r *AccessRepository) ReplaceUserRoles(ctx context.Context, userID int64, roleIDs []int64) error {
	queries := r.db.Queries(ctx)
	if err := queries.DeleteUserNonSystemRoles(ctx, userID); err != nil {
		return wrap("delete user roles", err)
	}

	if err := queries.AddUserRoles(ctx, sqlc.AddUserRolesParams{UserID: userID, RoleIds: roleIDs}); err != nil {
		return wrap("add user roles", err)
	}

	return nil
}

// mapRole converts a generated sqlc.Role row to the domain model.
func mapRole(row sqlc.Role) *domain.Role {
	return &domain.Role{
		ID:        row.ID,
		UUID:      row.UUID,
		Code:      row.Code,
		Name:      row.Name,
		IsSystem:  row.IsSystem,
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
	}
}

// wrap adds the failed operation to err; domain errors stay matchable with errors.Is/As.
var wrap = database.ErrorPrefixer("access repository")
