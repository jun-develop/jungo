package v1

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/jun-develop/junkit/apidoc"

	v1dto "jungo/internal/features/auth/dto/v1"
	v1handler "jungo/internal/features/auth/handler/v1"
	"jungo/internal/middleware"
)

// AuthRoutes registers the auth feature's endpoints under a version group.
type AuthRoutes struct {
	handler      *v1handler.AuthHandler
	authenticate middleware.Authenticate
	guard        *middleware.Guard
}

// NewAuthRoutes creates an AuthRoutes.
func NewAuthRoutes(handler *v1handler.AuthHandler, authenticate middleware.Authenticate, guard *middleware.Guard) *AuthRoutes {
	return &AuthRoutes{handler: handler, authenticate: authenticate, guard: guard}
}

// Version implements router.Versioned; routes are nested under "/api/v1".
func (r *AuthRoutes) Version() string {
	return "v1"
}

// Register implements router.Routes.
func (r *AuthRoutes) Register(group *gin.RouterGroup) {
	auth := group.Group("/auth")
	auth.POST("/login", r.guard.Public(r.handler.Login))
	auth.POST("/refresh", r.guard.Public(r.handler.Refresh))
	auth.POST("/forgot-password", r.guard.Public(r.handler.ForgotPassword))
	auth.POST("/reset-password", r.guard.Public(r.handler.ResetPassword))

	session := group.Group("/auth", gin.HandlerFunc(r.authenticate))
	session.POST("/logout", r.guard.Authenticated(r.handler.Logout))
	session.POST("/logout-all", r.guard.Authenticated(r.handler.LogoutAll))
	session.GET("/me", r.guard.Authenticated(r.handler.Me))
	session.GET("/sessions", r.guard.Authenticated(r.handler.ListSessions))
}

// Docs implements router.Documented.
func (r *AuthRoutes) Docs() []apidoc.Route {
	device := "Send an X-Device-ID header to keep one session per device."
	pair := v1dto.TokenPairResponse{}

	return []apidoc.Route{
		{Method: http.MethodPost, Path: "/auth/login", Summary: "Log in", Description: device, Body: v1dto.LoginRequest{}, Response: pair},
		{Method: http.MethodPost, Path: "/auth/refresh", Summary: "Exchange a refresh token for a new pair", Description: device, Body: v1dto.RefreshRequest{}, Response: pair},
		{Method: http.MethodPost, Path: "/auth/forgot-password", Summary: "Email a password reset link", Description: "Answers the same whether or not the email exists.", Body: v1dto.ForgotPasswordRequest{}},
		{Method: http.MethodPost, Path: "/auth/reset-password", Summary: "Set a new password with a reset token", Body: v1dto.ResetPasswordRequest{}},
		{Method: http.MethodPost, Path: "/auth/logout", Summary: "End this session"},
		{Method: http.MethodPost, Path: "/auth/logout-all", Summary: "End every session of this user"},
		{Method: http.MethodGet, Path: "/auth/me", Summary: "The current user, session and permissions", Response: v1dto.MeResponse{}},
		{Method: http.MethodGet, Path: "/auth/sessions", Summary: "This user's active sessions", Response: []v1dto.SessionSummaryResponse{}},
	}
}
