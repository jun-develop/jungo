package v1

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/jun-develop/junkit/pagination"
	"github.com/jun-develop/junkit/response"
	"github.com/jun-develop/junkit/validation"

	"jungo/internal/features/audit/domain"
	v1dto "jungo/internal/features/audit/dto/v1"
)

// AuditHandler adapts HTTP requests to domain.AuditService calls.
type AuditHandler struct {
	service   domain.AuditService
	responder response.Responder
	validator *validation.Validator
}

// NewAuditHandler creates an AuditHandler.
func NewAuditHandler(
	service domain.AuditService,
	responder response.Responder,
	validator *validation.Validator,
) *AuditHandler {
	return &AuditHandler{service: service, responder: responder, validator: validator}
}

// ListAuditLogs handles GET /audit-logs.
func (h *AuditHandler) ListAuditLogs(ctx *gin.Context) {
	var req v1dto.ListAuditLogsRequest
	if !validation.BindQuery(ctx, h.responder, h.validator, &req) {
		return
	}

	req.SetDefaults()

	items, total, err := h.service.ListAuditLogs(ctx.Request.Context(), v1dto.ToAuditLogListFilter(req))
	if err != nil {
		h.responder.Error(ctx, err)
		return
	}

	meta := pagination.NewPagination(req.Page, req.PageSize, total)
	h.responder.Pagination(ctx, http.StatusOK, "audit_logs_listed", v1dto.NewAuditLogResponseList(items), meta)
}
