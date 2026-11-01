package access

import (
	"context"
	"fmt"

	"go.uber.org/fx"

	"github.com/jun-develop/junkit/i18n"

	"jungo/internal/features/access/adapter"
	"jungo/internal/features/access/domain"
	v1handler "jungo/internal/features/access/handler/v1"
	"jungo/internal/features/access/infrastructure"
	"jungo/internal/features/access/repository"
	v1route "jungo/internal/features/access/router/v1"
	"jungo/internal/features/access/service"
	userdomain "jungo/internal/features/user/domain"
	"jungo/internal/middleware"
	"jungo/internal/router"
)

// Module wires the access feature's dependencies into the application's Fx graph.
var Module = fx.Module("access",
	fx.Provide(
		fx.Annotate(
			repository.NewAccessRepository,
			fx.As(new(domain.AccessRepository)),
			fx.As(new(userdomain.PermissionReader)),
		),
	),
	fx.Provide(
		fx.Annotate(
			adapter.NewUserAdapter,
			fx.As(new(domain.UserLookup)),
		),
	),
	fx.Provide(
		fx.Annotate(
			infrastructure.NewPermissionCache,
			fx.As(new(domain.PermissionCache)),
		),
	),
	// Permission codes this feature checks; NewAccessService receives every feature's codes.
	fx.Provide(
		fx.Annotate(
			func() []string { return domain.Permissions },
			fx.ResultTags(`group:"permissions,flatten"`),
		),
	),
	fx.Provide(
		fx.Annotate(
			service.NewAccessService,
			fx.ParamTags(``, ``, ``, ``, `group:"permissions"`),
			fx.As(new(domain.AccessService)),
			fx.As(new(middleware.PermissionLoader)),
		),
	),
	// Permission guard shared with other features' routers.
	fx.Provide(middleware.NewGuard),
	fx.Provide(v1handler.NewAccessHandler),
	fx.Provide(
		fx.Annotate(
			v1route.NewAccessRoutes,
			fx.As(new(router.Routes)),
			fx.ResultTags(`group:"routes"`),
		),
	),

	fx.Invoke(registerTranslations),
	fx.Invoke(registerPermissionCheck),
)

// registerPermissionCheck stops the app on start when a permission a feature uses is missing from
// the database. It only reads: the app never writes permissions.
func registerPermissionCheck(lc fx.Lifecycle, svc domain.AccessService) {
	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			if err := svc.CheckPermissions(ctx); err != nil {
				return fmt.Errorf("access: %w", err)
			}

			return nil
		},
	})
}

// registerTranslations registers this feature's messages and the display names of its permissions.
func registerTranslations(translator *i18n.Translator) {
	translator.AddTranslations(map[string]map[string]string{
		i18n.LangEN: {
			"permissions_listed":             "Permissions listed successfully",
			"roles_listed":                   "Roles listed successfully",
			"role_retrieved":                 "Role retrieved successfully",
			"role_created":                   "Role created successfully",
			"role_updated":                   "Role updated successfully",
			"role_deleted":                   "Role deleted successfully",
			"user_roles_listed":              "User roles listed successfully",
			"user_roles_updated":             "User roles updated successfully",
			"cannot_grant_unheld_permission": "This change involves a permission you do not hold yourself",
			"role_not_found":                 "Role not found",
			"role_already_exists":            "A role with this code already exists",
			"system_role_immutable":          "System roles cannot be changed",
			"cannot_change_own_roles":        "You cannot change your own roles",
			"cannot_manage_stronger_user":    "This user holds permissions you do not hold yourself",
			"unknown_permission":             "Unknown permission",
			"invalid_role_code":              "Role code must use lowercase letters and underscores",
			"invalid_role_name":              "Role name is required",

			"permission_group.access": "Access control",

			"permission.roles.read":   "View roles and permissions",
			"permission.roles.create": "Create roles",
			"permission.roles.update": "Edit roles and their permissions",
			"permission.roles.delete": "Delete roles",
			"permission.roles.assign": "Assign roles to users",
		},
	})
}
