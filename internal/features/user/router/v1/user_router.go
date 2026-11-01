package v1

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/jun-develop/junkit/response"

	authdomain "jungo/internal/features/auth/domain"
	"jungo/internal/features/user/domain"
	v1handler "jungo/internal/features/user/handler/v1"
	"jungo/internal/middleware"
	"jungo/internal/router"
)

// UserRoutes registers the user feature's endpoints under a version group.
type UserRoutes struct {
	handler       *v1handler.UserHandler
	authenticator middleware.Authenticator[*authdomain.Identity]
	guard         *middleware.Guard
	responder     response.Responder
}

// NewUserRoutes creates a UserRoutes.
func NewUserRoutes(handler *v1handler.UserHandler, authenticator middleware.Authenticator[*authdomain.Identity], guard *middleware.Guard, responder response.Responder) *UserRoutes {
	return &UserRoutes{handler: handler, authenticator: authenticator, guard: guard, responder: responder}
}

// Version implements router.Versioned; routes are nested under "/api/v1".
func (r *UserRoutes) Version() string {
	return "v1"
}

// Register implements router.Routes; every route requires a logged-in user. Authenticated routes
// act on a single user: the service allows the user themself, or a holder of the permission who
// also holds every permission of that user (UserService.authorize).
func (r *UserRoutes) Register(group *gin.RouterGroup) {
	users := group.Group("/users")
	users.Use(middleware.BearerAuth(r.authenticator, r.responder, middleware.BearerAuthOptions{}))

	users.POST("", r.guard.Can(r.handler.CreateUser, domain.UsersCreate))
	users.GET("", r.guard.Can(r.handler.ListUsers, domain.UsersRead))
	users.GET("/:uuid", r.guard.Authenticated(r.handler.GetUser))
	users.PATCH("/:uuid", r.guard.Authenticated(r.handler.UpdateUser))
	users.DELETE("/:uuid", r.guard.Can(r.handler.DeleteUser, domain.UsersDelete))
	users.POST("/:uuid/avatar", r.guard.Authenticated(r.handler.UploadAvatar))
	users.DELETE("/:uuid/avatar", r.guard.Authenticated(r.handler.DeleteAvatar))
}

// multipartOverhead is the room left in a body limit for multipart boundaries and part headers.
const multipartOverhead = 64 << 10

// BodyLimits implements router.BodyLimited; the avatar upload is larger than SECURITY_MAX_BODY_SIZE.
func (r *UserRoutes) BodyLimits() []router.BodyLimit {
	return []router.BodyLimit{
		{
			Method:   http.MethodPost,
			Path:     "/users/:uuid/avatar",
			MaxBytes: v1handler.MaxAvatarFileSize + multipartOverhead,
		},
	}
}
