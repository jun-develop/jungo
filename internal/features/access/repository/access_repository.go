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

// GetUserPermissions implements domain.AccessRepository.
func (r *AccessRepository) GetUserPermissions(ctx context.Context, userID int64) ([]string, error) {
	return r.db.Queries(ctx).GetUserPermissions(ctx, userID)
}

// GetActorAndTargetPermissions implements userdomain.PermissionReader.
func (r *AccessRepository) GetActorAndTargetPermissions(ctx context.Context, actorID, targetID int64) (actor, target []string, err error) {
	row, err := r.db.Queries(ctx).GetActorAndTargetPermissions(ctx, sqlc.GetActorAndTargetPermissionsParams{
		ActorID:  actorID,
		TargetID: targetID,
	})
	if err != nil {
		return nil, nil, err
	}

	return row.ActorPermissions, row.TargetPermissions, nil
}

// ListPermissions implements domain.AccessRepository; ordered by group, then code.
func (r *AccessRepository) ListPermissions(ctx context.Context) ([]domain.Permission, error) {
	rows, err := r.db.Queries(ctx).ListPermissions(ctx)
	if err != nil {
		return nil, err
	}

	return slicex.Map(rows, func(row sqlc.ListPermissionsRow) domain.Permission {
		return domain.Permission{Code: row.Code, Group: row.GroupCode}
	}), nil
}

// CreateRole implements domain.AccessRepository.
func (r *AccessRepository) CreateRole(ctx context.Context, code, name string) (*domain.Role, error) {
	row, err := r.db.Queries(ctx).CreateRole(ctx, sqlc.CreateRoleParams{Code: code, Name: name})
	if err != nil {
		return nil, database.Match(err, map[database.ErrorType]error{
			database.ErrorUniqueViolation: domain.ErrRoleAlreadyExists,
		})
	}

	return mapRole(row), nil
}

// ListRoles implements domain.AccessRepository; nil uuids lists every role. Each role carries its
// permissions and user count.
func (r *AccessRepository) ListRoles(ctx context.Context, uuids []uuid.UUID) ([]*domain.Role, error) {
	rows, err := r.db.Queries(ctx).ListRoles(ctx, uuids)
	if err != nil {
		return nil, err
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
	return r.db.Queries(ctx).LockRoles(ctx, uuids)
}

// UpdateRoleName implements domain.AccessRepository.
func (r *AccessRepository) UpdateRoleName(ctx context.Context, roleID int64, name string) error {
	_, err := r.db.Queries(ctx).UpdateRoleName(ctx, sqlc.UpdateRoleNameParams{ID: roleID, Name: name})
	return database.MatchNotFound(err, domain.ErrRoleNotFound)
}

// DeleteRole implements domain.AccessRepository; system roles are never deleted. Grants and
// assignments cascade.
func (r *AccessRepository) DeleteRole(ctx context.Context, roleID int64) error {
	n, err := r.db.Queries(ctx).DeleteRole(ctx, roleID)
	if err != nil {
		return err
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
		return err
	}

	return queries.AddRolePermissions(ctx, sqlc.AddRolePermissionsParams{RoleID: roleID, Codes: codes})
}

// ListUserIDsByRole implements domain.AccessRepository.
func (r *AccessRepository) ListUserIDsByRole(ctx context.Context, roleID int64) ([]int64, error) {
	return r.db.Queries(ctx).ListUserIDsByRole(ctx, roleID)
}

// ListUserRoles implements domain.AccessRepository; the roles carry no permissions or user count.
func (r *AccessRepository) ListUserRoles(ctx context.Context, userID int64) ([]*domain.Role, error) {
	rows, err := r.db.Queries(ctx).ListUserRoles(ctx, userID)
	if err != nil {
		return nil, err
	}

	return slicex.Map(rows, mapRole), nil
}

// ReplaceUserRoles implements domain.AccessRepository; it keeps the user's system roles. Call it
// inside a transaction.
func (r *AccessRepository) ReplaceUserRoles(ctx context.Context, userID int64, roleIDs []int64) error {
	queries := r.db.Queries(ctx)
	if err := queries.DeleteUserNonSystemRoles(ctx, userID); err != nil {
		return err
	}

	return queries.AddUserRoles(ctx, sqlc.AddUserRolesParams{UserID: userID, RoleIds: roleIDs})
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
