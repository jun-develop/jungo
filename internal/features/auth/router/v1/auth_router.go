package v1

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/jun-develop/junkit/apidoc"
	"github.com/jun-develop/junkit/response"

	"jungo/internal/features/auth/domain"
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
	session.POST("/logout-others", r.guard.Authenticated(r.handler.LogoutOthers))
	session.POST("/change-password", r.guard.Authenticated(r.handler.ChangePassword))
	session.GET("/me", r.guard.Authenticated(r.handler.Me))
	session.GET("/sessions", r.guard.Authenticated(r.handler.ListSessions))
	session.DELETE("/sessions/:family_uuid", r.guard.Authenticated(r.handler.RevokeSession))
}

// Docs implements router.Documented.
func (r *AuthRoutes) Docs() []apidoc.Route {
	device := []apidoc.Header{{Name: "X-Device-ID", Description: "A stable id of the client device; one session is kept per device."}}
	pair := v1dto.TokenPairResponse{}

	return []apidoc.Route{
		{
			ID: "login", Method: http.MethodPost, Path: "/auth/login", Summary: "Log in",
			Body: v1dto.LoginRequest{}, Headers: device, Response: pair,
			Errors: []*response.AppError{
				domain.ErrInvalidCredentials, domain.ErrInvalidCredentialsWarning, domain.ErrUserInactive,
				domain.ErrRecaptchaFailed, domain.ErrTooManyAttempts, domain.ErrIPBlocked,
			},
		},
		{
			ID: "refreshToken", Method: http.MethodPost, Path: "/auth/refresh", Summary: "Exchange a refresh token for a new pair",
			Body: v1dto.RefreshRequest{}, Headers: device, Response: pair,
			Errors: []*response.AppError{
				domain.ErrInvalidToken, domain.ErrInvalidTokenType, domain.ErrTokenExpired, domain.ErrTokenRevoked,
				domain.ErrTokenReused, domain.ErrUserInactive,
			},
		},
		{
			ID: "forgotPassword", Method: http.MethodPost, Path: "/auth/forgot-password", Summary: "Email a password reset link",
			Description: "Answers the same whether or not the email exists.", Body: v1dto.ForgotPasswordRequest{},
			Errors: []*response.AppError{domain.ErrTooManyResetRequests, domain.ErrPasswordResetUnavailable},
		},
		{
			ID: "resetPassword", Method: http.MethodPost, Path: "/auth/reset-password", Summary: "Set a new password with a reset token",
			Body:   v1dto.ResetPasswordRequest{},
			Errors: []*response.AppError{domain.ErrInvalidResetToken, domain.ErrPasswordTooLong},
		},
		{ID: "logout", Method: http.MethodPost, Path: "/auth/logout", Summary: "End this session"},
		{ID: "logoutAll", Method: http.MethodPost, Path: "/auth/logout-all", Summary: "End every session of this user"},
		{ID: "logoutOthers", Method: http.MethodPost, Path: "/auth/logout-others", Summary: "End every other session of this user", Description: "Keeps the session of this request."},
		{
			ID: "changePassword", Method: http.MethodPost, Path: "/auth/change-password", Summary: "Change your password",
			Description: "Ends your other sessions and keeps this one. Wrong current passwords count as failed logins from your IP.",
			Body:        v1dto.ChangePasswordRequest{},
			Errors: []*response.AppError{
				domain.ErrInvalidCurrentPassword, domain.ErrNewPasswordSameAsCurrent, domain.ErrPasswordTooLong,
				domain.ErrTooManyAttempts, domain.ErrIPBlocked,
			},
		},
		{ID: "getMe", Method: http.MethodGet, Path: "/auth/me", Summary: "The current user, session and permissions", Response: v1dto.MeResponse{}},
		{ID: "listSessions", Method: http.MethodGet, Path: "/auth/sessions", Summary: "This user's active sessions", Response: []v1dto.SessionSummaryResponse{}},
		{
			ID: "revokeSession", Method: http.MethodDelete, Path: "/auth/sessions/:family_uuid", Summary: "End one of your sessions",
			Description: "Ending the session of this request logs it out. Another user's session, or one that has ended, is session_not_found.",
			Errors:      []*response.AppError{domain.ErrSessionNotFound},
		},
	}
}
