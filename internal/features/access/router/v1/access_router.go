package v1

import (
	"github.com/gin-gonic/gin"

	"github.com/jun-develop/junkit/response"

	"jungo/internal/features/access/domain"
	v1handler "jungo/internal/features/access/handler/v1"
	authdomain "jungo/internal/features/auth/domain"
	"jungo/internal/middleware"
)

// AccessRoutes registers the access feature's endpoints under a version group.
type AccessRoutes struct {
	handler       *v1handler.AccessHandler
	authenticator middleware.Authenticator[*authdomain.Identity]
	guard         *middleware.Guard
	responder     response.Responder
}

// NewAccessRoutes creates an AccessRoutes.
func NewAccessRoutes(handler *v1handler.AccessHandler, authenticator middleware.Authenticator[*authdomain.Identity], guard *middleware.Guard, responder response.Responder) *AccessRoutes {
	return &AccessRoutes{handler: handler, authenticator: authenticator, guard: guard, responder: responder}
}

// Version implements router.Versioned; routes are nested under "/api/v1".
func (r *AccessRoutes) Version() string {
	return "v1"
}

// Register implements router.Routes; every route requires a logged-in user holding its permission.
func (r *AccessRoutes) Register(group *gin.RouterGroup) {
	auth := middleware.BearerAuth(r.authenticator, r.responder, middleware.BearerAuthOptions{})

	permissions := group.Group("/permissions", auth)
	permissions.GET("", r.guard.Can(r.handler.ListPermissions, domain.RolesRead))

	roles := group.Group("/roles", auth)
	roles.GET("", r.guard.Can(r.handler.ListRoles, domain.RolesRead))
	roles.POST("", r.guard.Can(r.handler.CreateRole, domain.RolesCreate))
	roles.GET("/:uuid", r.guard.Can(r.handler.GetRole, domain.RolesRead))
	roles.PATCH("/:uuid", r.guard.Can(r.handler.UpdateRole, domain.RolesUpdate))
	roles.PUT("/:uuid/permissions", r.guard.Can(r.handler.SetRolePermissions, domain.RolesUpdate))
	roles.DELETE("/:uuid", r.guard.Can(r.handler.DeleteRole, domain.RolesDelete))

	// Shares "/users/:uuid" with the user feature's routes.
	userRoles := group.Group("/users/:uuid/roles", auth)
	userRoles.GET("", r.guard.Can(r.handler.ListUserRoles, domain.RolesRead))
	userRoles.PUT("", r.guard.Can(r.handler.SetUserRoles, domain.RolesAssign))
}
