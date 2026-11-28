package v1

import (
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/jun-develop/junkit/pagination"
	"github.com/jun-develop/junkit/slicex"

	"jungo/internal/common/actor"
	"jungo/internal/features/access/domain"
)

// PermissionResponse is one permission.
type PermissionResponse struct {
	Code actor.PermissionCode `json:"code"`
	Name string               `json:"name"`
}

// PermissionGroupResponse is a permission group with its permissions.
type PermissionGroupResponse struct {
	Code        string               `json:"code"`
	Name        string               `json:"name"`
	Permissions []PermissionResponse `json:"permissions"`
}

// NewPermissionGroupResponseList converts permission groups to responses, naming each entry with
// translate ("permission_group.<group>", "permission.<resource>.<action>").
func NewPermissionGroupResponseList(groups []domain.PermissionGroup, translate func(key string, args ...any) string) []PermissionGroupResponse {
	return slicex.Map(groups, func(g domain.PermissionGroup) PermissionGroupResponse {
		perms := slicex.Map(g.Permissions, func(p domain.Permission) PermissionResponse {
			return PermissionResponse{Code: actor.PermissionCode(p.Code), Name: translate(PermissionLabelKey(p.Code))}
		})

		return PermissionGroupResponse{Code: g.Code, Name: translate(GroupLabelKey(g.Code)), Permissions: perms}
	})
}

// PermissionLabelKey returns the i18n key naming a permission code.
func PermissionLabelKey(code string) string {
	return "permission." + strings.ReplaceAll(code, ":", ".")
}

// GroupLabelKey returns the i18n key naming a permission group.
func GroupLabelKey(group string) string {
	return "permission_group." + group
}

// CreateRoleRequest is the request body for POST /roles; code is lowercase letters and underscores
// (pattern must match the service's roleCodePattern).
type CreateRoleRequest struct {
	Code        string                 `json:"code" binding:"required,min=2,max=50" pattern:"^[a-z_]+$"`
	Name        string                 `json:"name" binding:"required,min=2,max=100"`
	Permissions []actor.PermissionCode `json:"permissions" binding:"omitempty,dive,required"`
}

// ToCreateRoleInput converts CreateRoleRequest to domain input.
func ToCreateRoleInput(req CreateRoleRequest) domain.CreateRoleInput {
	return domain.CreateRoleInput{Code: req.Code, Name: req.Name, Permissions: actor.CodeStrings(req.Permissions)}
}

// RenameRoleRequest is the request body for PATCH /roles/:uuid; the code never changes.
type RenameRoleRequest struct {
	Name string `json:"name" binding:"required,min=2,max=100"`
}

// ReplaceRolePermissionsRequest is the request body for PUT /roles/:uuid/permissions; [] clears the role.
type ReplaceRolePermissionsRequest struct {
	Permissions []actor.PermissionCode `json:"permissions" binding:"required,dive,required"`
}

// SetUserRolesRequest is the request body for PUT /users/:uuid/roles; [] removes every non-system role.
type SetUserRolesRequest struct {
	RoleUUIDs []uuid.UUID `json:"role_uuids" binding:"required"`
}

// ListRolesRequest binds the query of GET /roles; search matches code or name.
type ListRolesRequest struct {
	pagination.PageRequest
	Search    string `form:"search" binding:"omitempty" example:"admin"`
	SortBy    string `form:"sort_by" binding:"omitempty,oneof=name code created_at user_count" example:"created_at"`
	SortOrder string `form:"sort_order" binding:"omitempty,oneof=asc desc" example:"desc"`
}

// ToRoleListFilter converts ListRolesRequest to the domain filter, newest first unless asked otherwise.
func ToRoleListFilter(req ListRolesRequest) domain.RoleListFilter {
	filter := domain.RoleListFilter{
		Search:    req.Search,
		SortBy:    req.SortBy,
		SortOrder: req.SortOrder,
		Limit:     req.GetLimit(),
		Offset:    req.GetOffset(),
	}

	if filter.SortBy == "" {
		filter.SortBy = "created_at"
	}

	if filter.SortOrder == "" {
		filter.SortOrder = "desc"
	}

	return filter
}

// RoleResponse represents the JSON response for a role.
type RoleResponse struct {
	UUID        uuid.UUID              `json:"uuid"`
	Code        string                 `json:"code"`
	Name        string                 `json:"name"`
	IsSystem    bool                   `json:"is_system"`
	Permissions []actor.PermissionCode `json:"permissions"`
	UserCount   int64                  `json:"user_count"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   *time.Time             `json:"updated_at"`
}

// NewRoleResponse converts domain.Role to RoleResponse.
func NewRoleResponse(r *domain.Role) RoleResponse {
	return RoleResponse{
		UUID:        r.UUID,
		Code:        r.Code,
		Name:        r.Name,
		IsSystem:    r.IsSystem,
		Permissions: actor.PermissionCodes(r.Permissions),
		UserCount:   r.UserCount,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}

// NewRoleResponseList converts a slice of domain.Role to RoleResponse list.
func NewRoleResponseList(roles []*domain.Role) []RoleResponse {
	return slicex.Map(roles, NewRoleResponse)
}

// UserRoleResponse is one role of a user.
type UserRoleResponse struct {
	UUID     uuid.UUID `json:"uuid"`
	Code     string    `json:"code"`
	Name     string    `json:"name"`
	IsSystem bool      `json:"is_system"`
}

// NewUserRoleResponseList converts a user's roles to responses.
func NewUserRoleResponseList(roles []*domain.Role) []UserRoleResponse {
	return slicex.Map(roles, func(r *domain.Role) UserRoleResponse {
		return UserRoleResponse{UUID: r.UUID, Code: r.Code, Name: r.Name, IsSystem: r.IsSystem}
	})
}
