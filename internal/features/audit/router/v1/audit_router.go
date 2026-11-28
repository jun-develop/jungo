package v1

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/jun-develop/junkit/apidoc"
	"github.com/jun-develop/junkit/response"

	"jungo/internal/features/audit/domain"
	v1dto "jungo/internal/features/audit/dto/v1"
	v1handler "jungo/internal/features/audit/handler/v1"
	"jungo/internal/middleware"
)

// AuditRoutes registers the audit feature's endpoints under a version group.
type AuditRoutes struct {
	handler      *v1handler.AuditHandler
	authenticate middleware.Authenticate
	guard        *middleware.Guard
}

// NewAuditRoutes creates an AuditRoutes.
func NewAuditRoutes(
	handler *v1handler.AuditHandler,
	authenticate middleware.Authenticate,
	guard *middleware.Guard,
) *AuditRoutes {
	return &AuditRoutes{handler: handler, authenticate: authenticate, guard: guard}
}

// Version implements router.Versioned; routes are nested under "/api/v1".
func (r *AuditRoutes) Version() string {
	return "v1"
}

// Register implements router.Routes; every route requires a logged-in user holding audit_logs:read.
func (r *AuditRoutes) Register(group *gin.RouterGroup) {
	logs := group.Group("/audit-logs", gin.HandlerFunc(r.authenticate))

	logs.GET("", r.guard.Can(r.handler.ListAuditLogs, domain.AuditLogsRead))
}

// Docs implements router.Documented; it describes every route Register adds (the API docs at /docs).
func (r *AuditRoutes) Docs() []apidoc.Route {
	return []apidoc.Route{
		{
			ID: "listAuditLogs", Method: http.MethodGet, Path: "/audit-logs", Summary: "List audit entries",
			Description: "Newest first unless sort_order=asc. Each entry carries its actor and a label of its entity, so a client needs no other read to show it.",
			Query:       v1dto.ListAuditLogsRequest{}, Response: v1dto.AuditLogResponse{}, Paginated: true,
			Errors: []*response.AppError{domain.ErrEntityTypeRequired},
		},
	}
}
