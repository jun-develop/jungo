package command

import (
	"context"
	"fmt"

	"github.com/jun-develop/junkit/console"

	"jungo/internal/features/audit/domain"
)

// CleanupLogsCommand deletes the audit entries older than domain.Retention. Schedule it daily, so each
// run deletes about one day's rows.
//
// Usage:
//
//	make console CMD="audit:cleanup-logs"
type CleanupLogsCommand struct {
	auditService domain.AuditService
}

// NewCleanupLogsCommand creates an CleanupLogsCommand.
func NewCleanupLogsCommand(auditService domain.AuditService) *CleanupLogsCommand {
	return &CleanupLogsCommand{auditService: auditService}
}

// Signature implements console.Command.
func (c *CleanupLogsCommand) Signature() string {
	return "audit:cleanup-logs"
}

// Run implements console.Command.
func (c *CleanupLogsCommand) Run(ctx context.Context, _ []string) error {
	deleted, err := c.auditService.CleanupLogs(ctx)
	if err != nil {
		return fmt.Errorf("cleanup audit logs: %w", err)
	}

	console.Successf("Deleted %d expired audit entries", deleted)

	return nil
}
