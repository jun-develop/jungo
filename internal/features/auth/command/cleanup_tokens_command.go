package command

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/jun-develop/junkit/console"

	"jungo/internal/config"
	"jungo/internal/features/auth/domain"
)

// CleanupTokensCommand deletes tokens expired or revoked before the retention window. Exchanged
// refresh tokens stay until they would have expired, so their reuse is still detected.
//
// Usage:
//
//	make console CMD="auth:cleanup-tokens"
//	make console CMD="auth:cleanup-tokens" ARGS="-retention=72h"
type CleanupTokensCommand struct {
	authService domain.AuthService
	cfg         *config.Config
}

// NewCleanupTokensCommand creates a CleanupTokensCommand.
func NewCleanupTokensCommand(authService domain.AuthService, cfg *config.Config) *CleanupTokensCommand {
	return &CleanupTokensCommand{authService: authService, cfg: cfg}
}

// Signature implements console.Command.
func (c *CleanupTokensCommand) Signature() string {
	return "auth:cleanup-tokens"
}

// Run implements console.Command.
func (c *CleanupTokensCommand) Run(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet(c.Signature(), flag.ContinueOnError)
	retention := flags.Duration("retention", c.cfg.Auth.RevokedRetention, "keep expired/revoked tokens this long")
	if err := flags.Parse(args); err != nil {
		return err
	}

	deleted, err := c.authService.CleanupTokens(ctx, *retention)
	if err != nil {
		return fmt.Errorf("cleanup tokens: %w", err)
	}

	console.Successf("Deleted %d auth tokens expired or revoked before %s", deleted, time.Now().Add(-*retention).Format(time.DateTime))

	return nil
}
