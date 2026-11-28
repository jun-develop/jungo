// Package private registers the auth feature's service-to-service endpoints.
package private

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/jun-develop/junkit/apidoc"
	"github.com/jun-develop/junkit/response"

	"jungo/internal/config"
	"jungo/internal/features/auth/domain"
	v1dto "jungo/internal/features/auth/dto/v1"
	v1handler "jungo/internal/features/auth/handler/v1"
	"jungo/internal/middleware"
)

// AuthRoutes registers the internal auth endpoints under "/api/internal/auth".
type AuthRoutes struct {
	handler   *v1handler.AuthHandler
	guard     *middleware.Guard
	cfg       *config.Config
	responder response.Responder
}

// NewAuthRoutes creates an AuthRoutes.
func NewAuthRoutes(handler *v1handler.AuthHandler, guard *middleware.Guard, cfg *config.Config, responder response.Responder) *AuthRoutes {
	return &AuthRoutes{handler: handler, guard: guard, cfg: cfg, responder: responder}
}

// Version implements router.Versioned; internal routes are not versioned.
func (r *AuthRoutes) Version() string {
	return ""
}

// Register implements router.Routes; every request is rejected while AUTH_INTERNAL_SECRET is unset.
func (r *AuthRoutes) Register(group *gin.RouterGroup) {
	requireSecret := middleware.RequireSecret(middleware.InternalSecretHeader, r.cfg.Auth.InternalSecret, r.responder)
	internal := group.Group("/internal/auth", requireSecret)

	internal.POST("/token-details", r.guard.Internal(r.handler.TokenDetails))
	internal.POST("/revoke", r.guard.Internal(r.handler.Revoke))
	internal.POST("/revoke-all", r.guard.Internal(r.handler.RevokeAll))
}

// Docs implements router.Documented.
func (r *AuthRoutes) Docs() []apidoc.Route {
	token := v1dto.TokenRequest{}
	invalid := []*response.AppError{domain.ErrInvalidToken, domain.ErrTokenNotFound}

	return []apidoc.Route{
		{
			ID: "getTokenDetails", Method: http.MethodPost, Path: "/internal/auth/token-details", Summary: "Resolve a token to its user and session",
			Body: token, Response: v1dto.TokenDetailsResponse{}, Errors: invalid,
		},
		{ID: "revokeToken", Method: http.MethodPost, Path: "/internal/auth/revoke", Summary: "Revoke the token's session", Body: token, Errors: invalid},
		{ID: "revokeAllTokens", Method: http.MethodPost, Path: "/internal/auth/revoke-all", Summary: "Revoke every session of the token's user", Body: token, Errors: invalid},
	}
}
