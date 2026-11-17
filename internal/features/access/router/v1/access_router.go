package v1

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/jun-develop/junkit/apidoc"

	"jungo/internal/features/access/domain"
	v1dto "jungo/internal/features/access/dto/v1"
	v1handler "jungo/internal/features/access/handler/v1"
	"jungo/internal/middleware"
)

// AccessRoutes registers the access feature's endpoints under a version group.
type AccessRoutes struct {
	handler      *v1handler.AccessHandler
	authenticate middleware.Authenticate
	guard        *middleware.Guard
}

// NewAccessRoutes creates an AccessRoutes.
func NewAccessRoutes(handler *v1handler.AccessHandler, authenticate middleware.Authenticate, guard *middleware.Guard) *AccessRoutes {
	return &AccessRoutes{handler: handler, authenticate: authenticate, guard: guard}
}

// Version implements router.Versioned; routes are nested under "/api/v1".
func (r *AccessRoutes) Version() string {
	return "v1"
}

// Register implements router.Routes; every route requires a logged-in user holding its permission.
func (r *AccessRoutes) Register(group *gin.RouterGroup) {
	auth := gin.HandlerFunc(r.authenticate)

	permissions := group.Group("/permissions", auth)
	permissions.GET("", r.guard.Can(r.handler.ListPermissions, domain.RolesRead))

	roles := group.Group("/roles", auth)
	roles.GET("", r.guard.Can(r.handler.ListRoles, domain.RolesRead))
	roles.POST("", r.guard.Can(r.handler.CreateRole, domain.RolesCreate))
	roles.GET("/:uuid", r.guard.Can(r.handler.GetRole, domain.RolesRead))
	roles.PATCH("/:uuid", r.guard.Can(r.handler.RenameRole, domain.RolesUpdate))
	roles.PUT("/:uuid/permissions", r.guard.Can(r.handler.ReplaceRolePermissions, domain.RolesUpdate))
	roles.DELETE("/:uuid", r.guard.Can(r.handler.DeleteRole, domain.RolesDelete))

	// Shares "/users/:uuid" with the user feature's routes.
	userRoles := group.Group("/users/:uuid/roles", auth)
	userRoles.GET("", r.guard.Can(r.handler.ListUserRoles, domain.RolesRead))
	userRoles.PUT("", r.guard.Can(r.handler.SetUserRoles, domain.RolesAssign))
}

// Docs implements router.Documented.
func (r *AccessRoutes) Docs() []apidoc.Route {
	role := v1dto.RoleResponse{}

	return []apidoc.Route{
		{Method: http.MethodGet, Path: "/permissions", Summary: "List permissions by group", Response: []v1dto.PermissionGroupResponse{}},
		{Method: http.MethodGet, Path: "/roles", Summary: "List roles", Response: []v1dto.RoleResponse{}},
		{Method: http.MethodPost, Path: "/roles", Summary: "Create a role", Description: "You can only grant permissions you hold.", Body: v1dto.CreateRoleRequest{}, Status: http.StatusCreated, Response: role},
		{Method: http.MethodGet, Path: "/roles/:uuid", Summary: "Get a role", Response: role},
		{Method: http.MethodPatch, Path: "/roles/:uuid", Summary: "Rename a role", Body: v1dto.RenameRoleRequest{}, Response: role},
		{Method: http.MethodPut, Path: "/roles/:uuid/permissions", Summary: "Replace a role's permissions", Description: "You can only grant permissions you hold.", Body: v1dto.ReplaceRolePermissionsRequest{}, Response: role},
		{Method: http.MethodDelete, Path: "/roles/:uuid", Summary: "Delete a role"},
		{Method: http.MethodGet, Path: "/users/:uuid/roles", Summary: "List a user's roles", Response: []v1dto.UserRoleResponse{}},
		{Method: http.MethodPut, Path: "/users/:uuid/roles", Summary: "Set a user's roles", Description: "You must hold every permission of the user and of each role you add or remove.", Body: v1dto.SetUserRolesRequest{}, Response: []v1dto.UserRoleResponse{}},
	}
}
