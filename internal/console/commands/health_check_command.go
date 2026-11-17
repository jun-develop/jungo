package commands

import (
	"context"
	"fmt"

	"github.com/jun-develop/junkit/console"

	"jungo/internal/database/primary"
)

// HealthCheckCommand pings the database and reports the number of users.
//
// Usage:
//
//	make console CMD="health:check"
type HealthCheckCommand struct {
	db *primary.DB
}

// NewHealthCheckCommand creates a HealthCheckCommand.
func NewHealthCheckCommand(db *primary.DB) *HealthCheckCommand {
	return &HealthCheckCommand{db: db}
}

// Signature implements console.Command.
func (c *HealthCheckCommand) Signature() string {
	return "health:check"
}

// Run implements console.Command.
func (c *HealthCheckCommand) Run(ctx context.Context, _ []string) error {
	if err := c.db.Ping(ctx); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}

	var count int64
	if err := c.db.Executor(ctx).QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		return fmt.Errorf("count users: %w", err)
	}

	console.Successf("Database reachable, %d user(s)", count)

	return nil
}
