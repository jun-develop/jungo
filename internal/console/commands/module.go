package commands

import (
	"go.uber.org/fx"

	"jungo/internal/console"
)

// Module registers global console commands.
var Module = fx.Options(
	// =============================================================================
	// COMMANDS
	// =============================================================================
	fx.Provide(
		fx.Annotate(
			NewMigrateCommand,
			fx.As(new(console.Command)),
			fx.ResultTags(`group:"commands"`),
		),
	),
	fx.Provide(
		fx.Annotate(
			NewHealthCheckCommand,
			fx.As(new(console.Command)),
			fx.ResultTags(`group:"commands"`),
		),
	),
)
