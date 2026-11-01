package auth

import (
	"go.uber.org/fx"

	"github.com/jun-develop/junkit/i18n"

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
	userdomain "jungo/internal/features/user/domain"
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
		fx.Annotate(
			adapter.NewSessionRevokerAdapter,
			fx.As(new(userdomain.SessionRevoker)),
		),
	),
	fx.Provide(
		fx.Annotate(
			service.NewAuthService,
			fx.As(new(domain.AuthService)),
		),
	),
	fx.Provide(newAccessAuthenticator),
	fx.Provide(v1handler.NewAuthHandler),
	fx.Provide(
		fx.Annotate(
			v1route.NewAuthRoutes,
			fx.As(new(router.Routes)),
			fx.ResultTags(`group:"routes"`),
		),
		fx.Annotate(
			privateroute.NewAuthRoutes,
			fx.As(new(router.Routes)),
			fx.ResultTags(`group:"routes"`),
		),
	),

	// =============================================================================
	// COMMANDS
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

// newAccessAuthenticator exposes AuthService.AuthenticateAccess as a middleware.Authenticator.
func newAccessAuthenticator(svc domain.AuthService) middleware.Authenticator[*domain.Identity] {
	return middleware.AuthenticatorFunc[*domain.Identity](svc.AuthenticateAccess)
}

// registerTranslations registers domain-specific translation messages.
func registerTranslations(translator *i18n.Translator) {
	translator.AddTranslations(map[string]map[string]string{
		i18n.LangEN: {
			"login_success":                 "Logged in successfully",
			"refresh_success":               "Token refreshed successfully",
			"logout_success":                "Logged out successfully",
			"logout_all_success":            "Logged out from all sessions successfully",
			"profile_retrieved":             "Profile retrieved successfully",
			"sessions_listed":               "Sessions listed successfully",
			"token_details_retrieved":       "Token details retrieved successfully",
			"token_revoked_success":         "Token revoked successfully",
			"tokens_revoked_all_success":    "All sessions of the user revoked successfully",
			"invalid_credentials":           "Invalid email or password",
			"invalid_credentials_warning":   "Invalid email or password. Further failed attempts will temporarily block logins from your IP",
			"user_account_is_not_active":    "Your account is not active",
			"too_many_login_attempts":       "Too many failed login attempts, please try again later",
			"ip_temporarily_blocked":        "Your IP has been temporarily blocked due to repeated failed logins",
			"recaptcha_verification_failed": "reCAPTCHA verification failed",
			"invalid_token":                 "Invalid token",
			"invalid_token_type":            "Invalid token type",
			"token_expired":                 "Token has expired",
			"token_revoked":                 "Token has been revoked",
			"token_reused":                  "Refresh token was already used; the session has been revoked, please log in again",
			"token_not_found":               "Token not found",
		},
	})
}
