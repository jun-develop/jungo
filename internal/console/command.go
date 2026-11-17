package console

import "context"

// Command is a CLI-invokable unit of work. Signature is its command-line name
// (e.g. "auth:cleanup-tokens"); Run receives the arguments that follow it.
type Command interface {
	Signature() string
	Run(ctx context.Context, args []string) error
}
