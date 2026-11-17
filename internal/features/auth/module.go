package auth

import (
	"go.uber.org/fx"

	"github.com/jun-develop/junkit/i18n"
	"github.com/jun-develop/junkit/response"

	"jungo/internal/console"
	"jungo/internal/features/auth/adapter"
	"jungo/internal/features/auth/command"
	"jungo/internal/features/auth/domain"
	v1handler "jungo/internal/features/auth/handler/v1"
	"jungo/internal/features/auth/infrastructure"
	"jungo/internal/features/auth/repository"
	privateroute "jungo/internal/features/auth/router/private"
	v1route "jungo/internal/features/auth/router/v1"
	"jungo/internal/features/auth/service"
	"jungo/internal/middleware"
	"jungo/internal/router"
)

// Module wires the auth feature's dependencies into the application's Fx graph.
var Module = fx.Module("auth",
	fx.Provide(
		fx.Annotate(
			repository.NewAuthRepository,
			fx.As(new(domain.AuthRepository)),
		),
	),
	fx.Provide(
		fx.Annotate(
			infrastructure.NewSessionCache,
			fx.As(new(domain.SessionCache)),
		),
	),
	fx.Provide(
		fx.Annotate(
			infrastructure.NewLoginGuard,
			fx.As(new(domain.LoginGuard)),
		),
	),
	fx.Provide(
		fx.Annotate(
			adapter.NewUserAdapter,
			fx.As(new(domain.UserProvider)),
		),
	),
	fx.Provide(
		fx.Annotate(
			service.NewAuthService,
			fx.As(new(domain.AuthService)),
		),
	),
	// The bearer-token middleware every feature's router protects its routes with.
	fx.Provide(newAuthenticate),
	fx.Provide(v1handler.NewAuthHandler),
	fx.Provide(
		fx.Annotate(
			v1route.NewAuthRoutes,
			fx.As(new(router.Routes)),
			fx.ResultTags(`group:"routes"`),
		),
	),
	fx.Provide(
		fx.Annotate(
			privateroute.NewAuthRoutes,
			fx.As(new(router.Routes)),
			fx.ResultTags(`group:"routes"`),
		),
	),

	// =============================================================================
	// COMMANDS (make command ... FEATURE=auth inserts here; keep this marker)
	// =============================================================================
	fx.Provide(
		fx.Annotate(
			command.NewCleanupTokensCommand,
			fx.As(new(console.Command)),
			fx.ResultTags(`group:"commands"`),
		),
	),

	fx.Invoke(registerTranslations),
)

// newAuthenticate builds the middleware that authenticates access tokens with AuthService.
func newAuthenticate(svc domain.AuthService, responder response.Responder) middleware.Authenticate {
	authenticator := middleware.AuthenticatorFunc[*domain.Identity](svc.AuthenticateAccess)
	return middleware.Authenticate(middleware.BearerAuth(authenticator, responder))
}

// registerTranslations registers this feature's messages.
func registerTranslations(translator *i18n.Translator) {
	translator.AddTranslations(map[string]map[string]string{
		i18n.LangEN: {
			"logged_in":                        "Logged in successfully",
			"token_refreshed":                  "Token refreshed successfully",
			"logged_out":                       "Logged out successfully",
			"logged_out_all":                   "Logged out from all sessions successfully",
			"profile_retrieved":                "Profile retrieved successfully",
			"sessions_listed":                  "Sessions listed successfully",
			"token_details_retrieved":          "Token details retrieved successfully",
			"session_revoked":                  "Session revoked successfully",
			"sessions_revoked":                 "All sessions of the user revoked successfully",
			"password_reset_requested":         "If an account exists for this email, a password reset link has been sent",
			"password_reset_completed":         "Your password has been reset; please log in again",
			"user_not_found":                   "User not found",
			"password_too_long":                "Password is too long (max 72 bytes; accented characters count as more than one)",
			"invalid_credentials":              "Invalid email or password",
			"invalid_credentials_warning":      "Invalid email or password. Further failed attempts will temporarily block logins from your IP",
			"user_account_is_not_active":       "Your account is not active",
			"too_many_login_attempts":          "Too many failed login attempts, please try again later",
			"ip_temporarily_blocked":           "Your IP has been temporarily blocked due to repeated failed logins",
			"recaptcha_verification_failed":    "reCAPTCHA verification failed",
			"invalid_token":                    "Invalid token",
			"invalid_token_type":               "Invalid token type",
			"token_expired":                    "Token has expired",
			"token_revoked":                    "Token has been revoked",
			"token_reused":                     "Refresh token was already used; the session has been revoked, please log in again",
			"token_not_found":                  "Token not found",
			"invalid_reset_token":              "This password reset link is invalid or has expired",
			"too_many_password_reset_requests": "Too many password reset requests, please try again later",
			"password_reset_unavailable":       "Password reset is currently unavailable",
		},
	})
}
