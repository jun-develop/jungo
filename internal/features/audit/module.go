package audit

import (
	"go.uber.org/fx"

	"github.com/jun-develop/junkit/i18n"

	"jungo/internal/common/auditlog"
	"jungo/internal/console"
	"jungo/internal/features/audit/command"
	"jungo/internal/features/audit/domain"
	v1handler "jungo/internal/features/audit/handler/v1"
	"jungo/internal/features/audit/repository"
	v1route "jungo/internal/features/audit/router/v1"
	"jungo/internal/features/audit/service"
	"jungo/internal/router"
)

// Module wires the audit feature's dependencies into the application's Fx graph.
var Module = fx.Module("audit",
	fx.Provide(
		fx.Annotate(
			repository.NewAuditRepository,
			fx.As(new(domain.AuditRepository)),
		),
	),
	fx.Provide(
		fx.Annotate(
			service.NewAuditService,
			fx.As(new(domain.AuditService)),
		),
	),
	// The Recorder the other features use (see provideAuditRecorder in internal/app); without this module they record nothing.
	fx.Provide(
		fx.Annotate(
			func(s domain.AuditService) auditlog.Recorder { return s },
			fx.ResultTags(`name:"audit"`),
		),
	),
	// Permission codes this feature checks; AccessService receives every feature's codes.
	fx.Provide(
		fx.Annotate(
			func() []string { return domain.Permissions },
			fx.ResultTags(`group:"permissions,flatten"`),
		),
	),
	fx.Provide(v1handler.NewAuditHandler),
	fx.Provide(
		fx.Annotate(
			v1route.NewAuditRoutes,
			fx.As(new(router.Routes)),
			fx.ResultTags(`group:"routes"`),
		),
	),

	// =============================================================================
	// COMMANDS (make command ... FEATURE=audit inserts here; keep this marker)
	// =============================================================================
	fx.Provide(
		fx.Annotate(
			command.NewCleanupLogsCommand,
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
			"permission_group.audit_logs": "Audit log",
			"permission.audit_logs.read":  "View the audit log",

			"entity_type_required": "entity_id needs entity_type",
			"audit_logs_listed":    "Audit entries listed successfully",
		},
	})
}
