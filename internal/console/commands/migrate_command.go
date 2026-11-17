package commands

import (
	"context"
	"fmt"

	"github.com/jun-develop/junkit/console"

	"jungo/internal/database/primary"
)

// MigrateCommand applies the pending migrations and the SQL functions built into the binary. The
// production stack runs it before the API starts (see deploy/docker-compose.yaml).
//
// Usage:
//
//	make console CMD="db:migrate"
type MigrateCommand struct {
	db *primary.DB
}

// NewMigrateCommand creates a MigrateCommand.
func NewMigrateCommand(db *primary.DB) *MigrateCommand {
	return &MigrateCommand{db: db}
}

// Signature implements console.Command.
func (c *MigrateCommand) Signature() string {
	return "db:migrate"
}

// Run implements console.Command.
func (c *MigrateCommand) Run(ctx context.Context, _ []string) error {
	applied, err := c.db.Migrate(ctx)
	for _, file := range applied {
		console.Infof("Applied %s", file)
	}

	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	console.Successf("Database is up to date")

	return nil
}
