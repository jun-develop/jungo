package domain

import "github.com/jun-develop/junkit/response"

// Domain errors for the access feature.
var (
	ErrRoleNotFound      = response.New(response.NotFound, "role_not_found")
	ErrRoleAlreadyExists = response.New(response.Conflict, "role_already_exists")
	ErrSystemRole        = response.New(response.Forbidden, "system_role_immutable")
	ErrUnknownPermission = response.New(response.UnprocessableEntity, "unknown_permission")
	ErrInvalidRoleCode   = response.New(response.UnprocessableEntity, "invalid_role_code")
	ErrInvalidRoleName   = response.New(response.UnprocessableEntity, "invalid_role_name")
	ErrUserNotFound      = response.New(response.NotFound, "user_not_found")
	ErrEscalation        = response.New(response.Forbidden, "cannot_grant_unheld_permission")

	ErrCannotChangeOwnRoles     = response.New(response.Forbidden, "cannot_change_own_roles")
	ErrCannotManageStrongerUser = response.New(response.Forbidden, "cannot_manage_stronger_user")
)
