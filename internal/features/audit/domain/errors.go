package domain

import "github.com/jun-develop/junkit/response"

// Domain errors for the audit feature.
var (
	ErrEntityTypeRequired = response.New(response.UnprocessableEntity, "entity_type_required")
)
