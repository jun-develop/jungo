package v1

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/jun-develop/junkit/response"
	"github.com/jun-develop/junkit/validation"

	"jungo/internal/features/access/domain"
	v1dto "jungo/internal/features/access/dto/v1"
)

// AccessHandler adapts HTTP requests to domain.AccessService calls.
type AccessHandler struct {
	service   domain.AccessService
	responder response.Responder
	validator *validation.Validator
}

// NewAccessHandler creates an AccessHandler.
func NewAccessHandler(service domain.AccessService, responder response.Responder, validator *validation.Validator) *AccessHandler {
	return &AccessHandler{service: service, responder: responder, validator: validator}
}

// ListPermissions handles GET /permissions; it returns every permission grouped for the UI.
func (h *AccessHandler) ListPermissions(ctx *gin.Context) {
	groups, err := h.service.ListPermissionGroups(ctx.Request.Context())
	if err != nil {
		h.responder.Error(ctx, err)
		return
	}

	h.responder.SendWithData(ctx, http.StatusOK, "permissions_listed", v1dto.NewPermissionGroupResponseList(groups, h.responder.Translate))
}

// ListRoles handles GET /roles.
func (h *AccessHandler) ListRoles(ctx *gin.Context) {
	roles, err := h.service.ListRoles(ctx.Request.Context())
	if err != nil {
		h.responder.Error(ctx, err)
		return
	}

	h.responder.SendWithData(ctx, http.StatusOK, "roles_listed", v1dto.NewRoleResponseList(roles))
}

// CreateRole handles POST /roles.
func (h *AccessHandler) CreateRole(ctx *gin.Context) {
	var req v1dto.CreateRoleRequest
	if !validation.BindJSON(ctx, h.responder, h.validator, &req) {
		return
	}

	role, err := h.service.CreateRole(ctx.Request.Context(), v1dto.ToCreateRoleInput(req))
	if err != nil {
		h.responder.Error(ctx, err)
		return
	}

	h.responder.SendWithData(ctx, http.StatusCreated, "role_created", v1dto.NewRoleResponse(role))
}

// GetRole handles GET /roles/:uuid.
func (h *AccessHandler) GetRole(ctx *gin.Context) {
	uid, ok := validation.ParseUUID(ctx, h.responder, h.validator)
	if !ok {
		return
	}

	role, err := h.service.GetRole(ctx.Request.Context(), uid)
	if err != nil {
		h.responder.Error(ctx, err)
		return
	}

	h.responder.SendWithData(ctx, http.StatusOK, "role_retrieved", v1dto.NewRoleResponse(role))
}

// UpdateRole handles PATCH /roles/:uuid.
func (h *AccessHandler) UpdateRole(ctx *gin.Context) {
	uid, ok := validation.ParseUUID(ctx, h.responder, h.validator)
	if !ok {
		return
	}

	var req v1dto.UpdateRoleRequest
	if !validation.BindJSON(ctx, h.responder, h.validator, &req) {
		return
	}

	role, err := h.service.RenameRole(ctx.Request.Context(), uid, req.Name)
	if err != nil {
		h.responder.Error(ctx, err)
		return
	}

	h.responder.SendWithData(ctx, http.StatusOK, "role_updated", v1dto.NewRoleResponse(role))
}

// SetRolePermissions handles PUT /roles/:uuid/permissions.
func (h *AccessHandler) SetRolePermissions(ctx *gin.Context) {
	uid, ok := validation.ParseUUID(ctx, h.responder, h.validator)
	if !ok {
		return
	}

	var req v1dto.SetRolePermissionsRequest
	if !validation.BindJSON(ctx, h.responder, h.validator, &req) {
		return
	}

	role, err := h.service.ReplaceRolePermissions(ctx.Request.Context(), uid, req.Permissions)
	if err != nil {
		h.responder.Error(ctx, err)
		return
	}

	h.responder.SendWithData(ctx, http.StatusOK, "role_updated", v1dto.NewRoleResponse(role))
}

// DeleteRole handles DELETE /roles/:uuid.
func (h *AccessHandler) DeleteRole(ctx *gin.Context) {
	uid, ok := validation.ParseUUID(ctx, h.responder, h.validator)
	if !ok {
		return
	}

	if err := h.service.DeleteRole(ctx.Request.Context(), uid); err != nil {
		h.responder.Error(ctx, err)
		return
	}

	h.responder.Send(ctx, http.StatusOK, "role_deleted")
}

// ListUserRoles handles GET /users/:uuid/roles.
func (h *AccessHandler) ListUserRoles(ctx *gin.Context) {
	uid, ok := validation.ParseUUID(ctx, h.responder, h.validator)
	if !ok {
		return
	}

	roles, err := h.service.ListUserRoles(ctx.Request.Context(), uid)
	if err != nil {
		h.responder.Error(ctx, err)
		return
	}

	h.responder.SendWithData(ctx, http.StatusOK, "user_roles_listed", v1dto.NewUserRoleResponseList(roles))
}

// SetUserRoles handles PUT /users/:uuid/roles.
func (h *AccessHandler) SetUserRoles(ctx *gin.Context) {
	uid, ok := validation.ParseUUID(ctx, h.responder, h.validator)
	if !ok {
		return
	}

	var req v1dto.SetUserRolesRequest
	if !validation.BindJSON(ctx, h.responder, h.validator, &req) {
		return
	}

	roles, err := h.service.SetUserRoles(ctx.Request.Context(), uid, req.RoleUUIDs)
	if err != nil {
		h.responder.Error(ctx, err)
		return
	}

	h.responder.SendWithData(ctx, http.StatusOK, "user_roles_updated", v1dto.NewUserRoleResponseList(roles))
}
