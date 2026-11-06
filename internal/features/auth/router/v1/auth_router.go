package v1

import (
	"github.com/gin-gonic/gin"

	"github.com/jun-develop/junkit/response"

	"jungo/internal/features/auth/domain"
	v1handler "jungo/internal/features/auth/handler/v1"
	"jungo/internal/middleware"
)

// AuthRoutes registers the auth feature's endpoints under a version group.
type AuthRoutes struct {
	handler       *v1handler.AuthHandler
	authenticator middleware.Authenticator[*domain.Identity]
	guard         *middleware.Guard
	responder     response.Responder
}

// NewAuthRoutes creates an AuthRoutes.
func NewAuthRoutes(handler *v1handler.AuthHandler, authenticator middleware.Authenticator[*domain.Identity], guard *middleware.Guard, responder response.Responder) *AuthRoutes {
	return &AuthRoutes{handler: handler, authenticator: authenticator, guard: guard, responder: responder}
}

// Version implements router.Versioned; routes are nested under "/api/v1".
func (r *AuthRoutes) Version() string {
	return "v1"
}

// Register implements router.Routes.
func (r *AuthRoutes) Register(group *gin.RouterGroup) {
	items := group.Group("/auth")

	items.POST("/login", r.guard.Public(r.handler.Login))
	items.POST("/refresh", r.guard.Public(r.handler.Refresh))
	items.POST("/forgot-password", r.guard.Public(r.handler.ForgotPassword))
	items.POST("/reset-password", r.guard.Public(r.handler.ResetPassword))

	protected := items.Group("", middleware.BearerAuth(r.authenticator, r.responder, middleware.BearerAuthOptions{}))
	protected.POST("/logout", r.guard.Authenticated(r.handler.Logout))
	protected.POST("/logout-all", r.guard.Authenticated(r.handler.LogoutAll))
	protected.GET("/me", r.guard.Authenticated(r.handler.Me))
	protected.GET("/sessions", r.guard.Authenticated(r.handler.Sessions))
}
