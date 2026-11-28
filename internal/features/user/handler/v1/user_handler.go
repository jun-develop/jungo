package v1

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/jun-develop/junkit/pagination"
	"github.com/jun-develop/junkit/response"
	"github.com/jun-develop/junkit/upload"
	"github.com/jun-develop/junkit/validation"

	"jungo/internal/common/actor"
	"jungo/internal/features/user/domain"
	v1dto "jungo/internal/features/user/dto/v1"
)

// MaxAvatarFileSize caps an uploaded avatar at 5MB; the route's body limit (see UserRoutes.BodyLimits)
// is derived from it.
const MaxAvatarFileSize = 5 << 20

// avatarRule is what UploadAvatar accepts: a JPEG, PNG or WebP image up to MaxAvatarFileSize.
var avatarRule = upload.Image(MaxAvatarFileSize)

// UserHandler adapts HTTP requests to domain.UserService calls.
type UserHandler struct {
	service   domain.UserService
	responder response.Responder
	validator *validation.Validator
}

// NewUserHandler creates a UserHandler.
func NewUserHandler(service domain.UserService, responder response.Responder, validator *validation.Validator) *UserHandler {
	return &UserHandler{service: service, responder: responder, validator: validator}
}

// CreateUser handles POST /users.
func (h *UserHandler) CreateUser(ctx *gin.Context) {
	var req v1dto.CreateUserRequest
	if !validation.BindJSON(ctx, h.responder, h.validator, &req) {
		return
	}

	user, err := h.service.CreateUser(ctx.Request.Context(), v1dto.ToCreateUserInput(req))
	if err != nil {
		h.responder.Error(ctx, err)
		return
	}

	h.responder.SendWithData(ctx, http.StatusCreated, "user_created", v1dto.NewUserResponse(user))
}

// GetUser handles GET /users/:uuid.
func (h *UserHandler) GetUser(ctx *gin.Context) {
	uid, ok := validation.ParseUUID(ctx, h.responder, h.validator)
	if !ok {
		return
	}

	user, err := h.service.GetUser(ctx.Request.Context(), uid)
	if err != nil {
		h.responder.Error(ctx, err)
		return
	}

	h.responder.SendWithData(ctx, http.StatusOK, "user_retrieved", v1dto.NewUserResponse(user))
}

// ListUsers handles GET /users.
func (h *UserHandler) ListUsers(ctx *gin.Context) {
	var req v1dto.ListUsersRequest
	if !validation.BindQuery(ctx, h.responder, h.validator, &req) {
		return
	}

	req.SetDefaults()

	users, total, err := h.service.ListUsers(ctx.Request.Context(), v1dto.ToUserListFilter(req))
	if err != nil {
		h.responder.Error(ctx, err)
		return
	}

	meta := pagination.NewPagination(req.Page, req.PageSize, total)
	h.responder.Pagination(ctx, http.StatusOK, "users_listed", v1dto.NewUserResponseList(users), meta)
}

// UpdateUser handles PATCH /users/:uuid.
func (h *UserHandler) UpdateUser(ctx *gin.Context) {
	uid, ok := validation.ParseUUID(ctx, h.responder, h.validator)
	if !ok {
		return
	}

	var req v1dto.UpdateUserRequest
	if !validation.BindJSON(ctx, h.responder, h.validator, &req) {
		return
	}

	user, err := h.service.UpdateUser(ctx.Request.Context(), uid, v1dto.ToUpdateUserInput(req))
	if err != nil {
		h.responder.Error(ctx, err)
		return
	}

	h.responder.SendWithData(ctx, http.StatusOK, "user_updated", v1dto.NewUserResponse(user))
}

// DeleteUser handles DELETE /users/:uuid.
func (h *UserHandler) DeleteUser(ctx *gin.Context) {
	uid, ok := validation.ParseUUID(ctx, h.responder, h.validator)
	if !ok {
		return
	}

	if err := h.service.DeleteUser(ctx.Request.Context(), uid); err != nil {
		h.responder.Error(ctx, err)
		return
	}

	h.responder.Send(ctx, http.StatusOK, "user_deleted")
}

// UploadAvatar handles POST /users/:uuid/avatar.
func (h *UserHandler) UploadAvatar(ctx *gin.Context) {
	if uid, ok := validation.ParseUUID(ctx, h.responder, h.validator); ok {
		h.uploadAvatar(ctx, uid)
	}
}

// DeleteAvatar handles DELETE /users/:uuid/avatar.
func (h *UserHandler) DeleteAvatar(ctx *gin.Context) {
	if uid, ok := validation.ParseUUID(ctx, h.responder, h.validator); ok {
		h.deleteAvatar(ctx, uid)
	}
}

// UpdateMe handles PATCH /auth/me: the logged-in user changes their own profile, which needs no
// permission.
func (h *UserHandler) UpdateMe(ctx *gin.Context) {
	var req v1dto.UpdateMeRequest
	if !validation.BindJSON(ctx, h.responder, h.validator, &req) {
		return
	}

	user, err := h.service.UpdateUser(ctx.Request.Context(), me(ctx), v1dto.ToUpdateMeInput(req))
	if err != nil {
		h.responder.Error(ctx, err)
		return
	}

	h.responder.SendWithData(ctx, http.StatusOK, "user_updated", v1dto.NewUserResponse(user))
}

// UploadMyAvatar handles POST /auth/me/avatar.
func (h *UserHandler) UploadMyAvatar(ctx *gin.Context) {
	h.uploadAvatar(ctx, me(ctx))
}

// DeleteMyAvatar handles DELETE /auth/me/avatar.
func (h *UserHandler) DeleteMyAvatar(ctx *gin.Context) {
	h.deleteAvatar(ctx, me(ctx))
}

// uploadAvatar stores the request's "avatar" file as the avatar of user uid.
func (h *UserHandler) uploadAvatar(ctx *gin.Context, uid uuid.UUID) {
	fileHeader, err := ctx.FormFile("avatar")
	if err != nil {
		h.responder.Error(ctx, domain.ErrInvalidAvatarFile)
		return
	}

	file, err := upload.Open(fileHeader, avatarRule)
	if err != nil {
		h.responder.Error(ctx, domain.ErrInvalidAvatarFile)
		return
	}

	defer file.Close()

	user, err := h.service.UploadAvatar(ctx.Request.Context(), uid, domain.AvatarFile{
		Reader:   file,
		Filename: fileHeader.Filename,
	})
	if err != nil {
		h.responder.Error(ctx, err)
		return
	}

	h.responder.SendWithData(ctx, http.StatusOK, "avatar_uploaded", v1dto.NewUserResponse(user))
}

// deleteAvatar removes the avatar of user uid.
func (h *UserHandler) deleteAvatar(ctx *gin.Context, uid uuid.UUID) {
	user, err := h.service.DeleteAvatar(ctx.Request.Context(), uid)
	if err != nil {
		h.responder.Error(ctx, err)
		return
	}

	h.responder.SendWithData(ctx, http.StatusOK, "avatar_deleted", v1dto.NewUserResponse(user))
}

// me returns the logged-in user's UUID; Guard.Authenticated stored the actor before the handler runs.
func me(ctx *gin.Context) uuid.UUID {
	a, _ := actor.From(ctx.Request.Context())
	return a.UserUUID
}
