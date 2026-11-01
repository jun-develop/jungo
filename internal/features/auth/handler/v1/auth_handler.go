package v1

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/jun-develop/junkit/response"
	"github.com/jun-develop/junkit/security"
	"github.com/jun-develop/junkit/validation"

	"jungo/internal/common/actor"
	"jungo/internal/features/auth/domain"
	v1dto "jungo/internal/features/auth/dto/v1"
)

// deviceIDHeader carries the client's stable device identifier (optional).
const deviceIDHeader = "X-Device-ID"

// AuthHandler adapts HTTP requests to domain.AuthService calls.
type AuthHandler struct {
	service   domain.AuthService
	responder response.Responder
	validator *validation.Validator
}

// NewAuthHandler creates an AuthHandler.
func NewAuthHandler(service domain.AuthService, responder response.Responder, validator *validation.Validator) *AuthHandler {
	return &AuthHandler{service: service, responder: responder, validator: validator}
}

// Login handles POST /auth/login.
func (h *AuthHandler) Login(ctx *gin.Context) {
	var req v1dto.LoginRequest
	if !validation.BindJSON(ctx, h.responder, h.validator, &req) {
		return
	}

	pair, err := h.service.Login(ctx.Request.Context(), v1dto.ToLoginInput(req, clientMetadata(ctx)))
	if err != nil {
		h.responder.Error(ctx, err)
		return
	}

	h.responder.SendWithData(ctx, http.StatusOK, "login_success", v1dto.NewTokenPairResponse(pair, time.Now()))
}

// Refresh handles POST /auth/refresh. The refresh token is read from the body only.
func (h *AuthHandler) Refresh(ctx *gin.Context) {
	var req v1dto.RefreshRequest
	if !validation.BindJSON(ctx, h.responder, h.validator, &req) {
		return
	}

	pair, err := h.service.Refresh(ctx.Request.Context(), req.RefreshToken, clientMetadata(ctx))
	if err != nil {
		h.responder.Error(ctx, err)
		return
	}

	h.responder.SendWithData(ctx, http.StatusOK, "refresh_success", v1dto.NewTokenPairResponse(pair, time.Now()))
}

// Logout handles POST /auth/logout.
func (h *AuthHandler) Logout(ctx *gin.Context) {
	identity := security.MustGetIdentity[*domain.Identity](ctx)

	if err := h.service.Logout(ctx.Request.Context(), identity); err != nil {
		h.responder.Error(ctx, err)
		return
	}

	h.responder.Send(ctx, http.StatusOK, "logout_success")
}

// LogoutAll handles POST /auth/logout-all.
func (h *AuthHandler) LogoutAll(ctx *gin.Context) {
	identity := security.MustGetIdentity[*domain.Identity](ctx)

	if err := h.service.LogoutAll(ctx.Request.Context(), identity); err != nil {
		h.responder.Error(ctx, err)
		return
	}

	h.responder.Send(ctx, http.StatusOK, "logout_all_success")
}

// Me handles GET /auth/me.
func (h *AuthHandler) Me(ctx *gin.Context) {
	identity := security.MustGetIdentity[*domain.Identity](ctx)

	// Guard.Authenticated stored the actor with the user's permissions.
	var permissions []string
	if a, ok := actor.From(ctx.Request.Context()); ok {
		permissions = a.Permissions
	}

	h.responder.SendWithData(ctx, http.StatusOK, "profile_retrieved", v1dto.NewMeResponse(identity.Session, permissions, time.Now()))
}

// Sessions handles GET /auth/sessions.
func (h *AuthHandler) Sessions(ctx *gin.Context) {
	identity := security.MustGetIdentity[*domain.Identity](ctx)

	items, err := h.service.ListSessions(ctx.Request.Context(), identity)
	if err != nil {
		h.responder.Error(ctx, err)
		return
	}

	h.responder.SendWithData(ctx, http.StatusOK, "sessions_listed", v1dto.NewSessionSummaryResponseList(items))
}

// TokenDetails handles POST /internal/auth/token-details.
func (h *AuthHandler) TokenDetails(ctx *gin.Context) {
	var req v1dto.TokenRequest
	if !validation.BindJSON(ctx, h.responder, h.validator, &req) {
		return
	}

	details, err := h.service.GetTokenDetails(ctx.Request.Context(), req.Token)
	if err != nil {
		h.responder.Error(ctx, err)
		return
	}

	h.responder.SendWithData(ctx, http.StatusOK, "token_details_retrieved", v1dto.NewTokenDetailsResponse(details, time.Now()))
}

// Revoke handles POST /internal/auth/revoke.
func (h *AuthHandler) Revoke(ctx *gin.Context) {
	var req v1dto.TokenRequest
	if !validation.BindJSON(ctx, h.responder, h.validator, &req) {
		return
	}

	if err := h.service.RevokeToken(ctx.Request.Context(), req.Token); err != nil {
		h.responder.Error(ctx, err)
		return
	}

	h.responder.Send(ctx, http.StatusOK, "token_revoked_success")
}

// RevokeAll handles POST /internal/auth/revoke-all.
func (h *AuthHandler) RevokeAll(ctx *gin.Context) {
	var req v1dto.TokenRequest
	if !validation.BindJSON(ctx, h.responder, h.validator, &req) {
		return
	}

	if err := h.service.RevokeAllTokens(ctx.Request.Context(), req.Token); err != nil {
		h.responder.Error(ctx, err)
		return
	}

	h.responder.Send(ctx, http.StatusOK, "tokens_revoked_all_success")
}

// clientMetadata extracts the client description stored with issued tokens.
func clientMetadata(ctx *gin.Context) domain.Metadata {
	return domain.Metadata{
		IPAddress: ctx.ClientIP(),
		UserAgent: ctx.Request.UserAgent(),
		DeviceID:  ctx.GetHeader(deviceIDHeader),
	}
}
