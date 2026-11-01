package domain

// Permission codes ("resource:action") the user feature checks; each must also be a row in the
// permissions table.
const (
	UsersRead   = "users:read"
	UsersCreate = "users:create"
	UsersUpdate = "users:update"
	UsersDelete = "users:delete"
)

// Permissions lists the user feature's permission codes; the module provides them to the
// "permissions" Fx group.
var Permissions = []string{UsersRead, UsersCreate, UsersUpdate, UsersDelete}
