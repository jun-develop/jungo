package auditlog

import "context"

// Actions shared by every feature; a feature may record its own, e.g. "set_roles".
const (
	ActionCreate = "create"
	ActionUpdate = "update"
	ActionDelete = "delete"
)

// Entry is one change to record. Who acted and the trace ID are taken from the context.
type Entry struct {
	Action     string
	EntityType string
	EntityID   string
	Before     map[string]any
	After      map[string]any
}

// Recorder writes entries to the audit log.
type Recorder interface {
	Record(ctx context.Context, e Entry) error
}

// Nop records nothing; the app uses it when the audit feature is not loaded.
type Nop struct{}

func (Nop) Record(context.Context, Entry) error {
	return nil
}
