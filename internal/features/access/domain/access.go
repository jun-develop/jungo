package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Role is a named set of permissions assigned to users.
type Role struct {
	ID          int64
	UUID        uuid.UUID
	Code        string
	Name        string
	IsSystem    bool
	CreatedAt   time.Time
	UpdatedAt   *time.Time
	Permissions []string
	UserCount   int64
}

// CreateRoleInput holds data for creating a role.
type CreateRoleInput struct {
	Code        string
	Name        string
	Permissions []string
}

// AccessRepository defines database operations for roles and permissions.
type AccessRepository interface {
	WithTransaction(ctx context.Context, fn func(ctx context.Context) error) error
	GetUserPermissions(ctx context.Context, userID int64) ([]string, error)
	ListPermissions(ctx context.Context) ([]Permission, error)
	CreateRole(ctx context.Context, code, name string) (*Role, error)
	ListRoles(ctx context.Context, uuids []uuid.UUID) ([]*Role, error)
	LockRoles(ctx context.Context, uuids []uuid.UUID) error
	UpdateRoleName(ctx context.Context, roleID int64, name string) error
	DeleteRole(ctx context.Context, roleID int64) error
	ReplaceRolePermissions(ctx context.Context, roleID int64, codes []string) error
	ListUserIDsByRole(ctx context.Context, roleID int64) ([]int64, error)
	ListUserRoles(ctx context.Context, userID int64) ([]*Role, error)
	ReplaceUserRoles(ctx context.Context, userID int64, roleIDs []int64) error
}

// UserLookup finds users by UUID; implemented over the user feature.
type UserLookup interface {
	GetUserID(ctx context.Context, uid uuid.UUID) (int64, error)
	LockUser(ctx context.Context, uid uuid.UUID) (int64, error)
}

// PermissionCache caches each user's permission codes.
type PermissionCache interface {
	GetOrLoad(ctx context.Context, userID int64, load func() ([]string, error)) ([]string, error)
	InvalidateUsers(ctx context.Context, userIDs ...int64)
	InvalidateAll(ctx context.Context)
}

// AccessService defines business logic for roles and permissions.
type AccessService interface {
	Permissions(ctx context.Context, userID int64) ([]string, error)
	IsPermission(code string) bool
	CheckPermissions(ctx context.Context) error
	ListPermissionGroups(ctx context.Context) ([]PermissionGroup, error)
	CreateRole(ctx context.Context, input CreateRoleInput) (*Role, error)
	GetRole(ctx context.Context, uid uuid.UUID) (*Role, error)
	ListRoles(ctx context.Context) ([]*Role, error)
	RenameRole(ctx context.Context, uid uuid.UUID, name string) (*Role, error)
	ReplaceRolePermissions(ctx context.Context, uid uuid.UUID, codes []string) (*Role, error)
	DeleteRole(ctx context.Context, uid uuid.UUID) error
	ListUserRoles(ctx context.Context, userUUID uuid.UUID) ([]*Role, error)
	SetUserRoles(ctx context.Context, userUUID uuid.UUID, roleUUIDs []uuid.UUID) ([]*Role, error)
}
