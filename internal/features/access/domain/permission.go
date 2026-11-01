package domain

// Permission is one row of the permissions table. Group only groups permissions in the UI; it can
// differ from the code's resource prefix.
type Permission struct {
	Code  string
	Group string
}

// Permission codes ("resource:action") the access feature checks; each must also be a row in the
// permissions table.
const (
	RolesRead   = "roles:read"
	RolesCreate = "roles:create"
	RolesUpdate = "roles:update"
	RolesDelete = "roles:delete"

	RolesAssign = "roles:assign"
)

// Permissions lists the access feature's permission codes. Every feature provides its own list to
// the "permissions" Fx group; AccessService checks the merged list against the database on start.
var Permissions = []string{RolesRead, RolesCreate, RolesUpdate, RolesDelete, RolesAssign}

// PermissionGroup is a group of permissions, as shown in the UI.
type PermissionGroup struct {
	Code        string
	Permissions []Permission
}

// GroupPermissions groups perms by Group, keeping the order in which groups first appear.
func GroupPermissions(perms []Permission) []PermissionGroup {
	var groups []PermissionGroup
	index := make(map[string]int)

	for _, p := range perms {
		i, ok := index[p.Group]
		if !ok {
			i = len(groups)
			index[p.Group] = i
			groups = append(groups, PermissionGroup{Code: p.Group})
		}

		groups[i].Permissions = append(groups[i].Permissions, p)
	}

	return groups
}
