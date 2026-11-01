package user

import (
	"go.uber.org/fx"

	"github.com/jun-develop/junkit/i18n"

	"jungo/internal/console"
	"jungo/internal/features/user/command"
	"jungo/internal/features/user/domain"
	v1handler "jungo/internal/features/user/handler/v1"
	"jungo/internal/features/user/repository"
	v1route "jungo/internal/features/user/router/v1"
	"jungo/internal/features/user/service"
	"jungo/internal/router"
)

// Module wires the user feature's dependencies into the application's Fx graph.
var Module = fx.Module("user",
	fx.Provide(
		fx.Annotate(
			repository.NewUserRepository,
			fx.As(new(domain.UserRepository)),
		),
	),
	fx.Provide(
		fx.Annotate(
			service.NewUserService,
			fx.As(new(domain.UserService)),
		),
	),
	fx.Provide(
		fx.Annotate(
			func() []string { return domain.Permissions },
			fx.ResultTags(`group:"permissions,flatten"`),
		),
	),
	fx.Provide(v1handler.NewUserHandler),
	fx.Provide(
		fx.Annotate(
			v1route.NewUserRoutes,
			fx.As(new(router.Routes)),
			fx.ResultTags(`group:"routes"`),
		),
	),

	// =============================================================================
	// COMMANDS
	// =============================================================================
	fx.Provide(
		fx.Annotate(
			command.NewCreateUserCommand,
			fx.As(new(console.Command)),
			fx.ResultTags(`group:"commands"`),
		),
	),
	fx.Provide(
		fx.Annotate(
			command.NewListUsersCommand,
			fx.As(new(console.Command)),
			fx.ResultTags(`group:"commands"`),
		),
	),

	fx.Invoke(registerTranslations),
)

// registerTranslations registers this feature's messages and the display names of its permissions.
func registerTranslations(translator *i18n.Translator) {
	translator.AddTranslations(map[string]map[string]string{
		i18n.LangEN: {
			"permission_group.users":  "Users",
			"permission.users.read":   "View users",
			"permission.users.create": "Create users",
			"permission.users.update": "Update users",
			"permission.users.delete": "Delete users",

			"user_not_found":       "User not found",
			"email_already_exists": "This email is already registered",
			"password_too_long":    "Password is too long (max 72 bytes; accented characters count as more than one)",
			"invalid_avatar_file":  "Invalid avatar file (allowed: jpg, jpeg, png, webp; max 5MB)",
			"user_created":         "User created successfully",
			"user_retrieved":       "User retrieved successfully",
			"users_listed":         "Users listed successfully",
			"user_updated":         "User updated successfully",
			"user_deleted":         "User deleted successfully",
			"avatar_uploaded":      "Avatar uploaded successfully",
			"avatar_deleted":       "Avatar deleted successfully",

			"cannot_manage_stronger_user": "This user holds permissions you do not hold yourself",
			"cannot_change_own_status":    "You cannot change your own status",
			"cannot_delete_self":          "You cannot delete your own account",
		},
	})
}
