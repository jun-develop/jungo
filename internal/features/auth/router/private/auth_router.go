// Package private registers the auth feature's service-to-service endpoints.
package private

import (
	"github.com/gin-gonic/gin"

	"github.com/jun-develop/junkit/response"

	"jungo/internal/config"
	v1handler "jungo/internal/features/auth/handler/v1"
	"jungo/internal/middleware"
)

// internalSecretHeader carries AUTH_INTERNAL_SECRET on internal calls.
const internalSecretHeader = "X-Internal-Secret"

// AuthRoutes registers the internal auth endpoints under "/api/internal/auth".
type AuthRoutes struct {
	handler   *v1handler.AuthHandler
	cfg       *config.Config
	responder response.Responder
}

// NewAuthRoutes creates an AuthRoutes.
func NewAuthRoutes(handler *v1handler.AuthHandler, cfg *config.Config, responder response.Responder) *AuthRoutes {
	return &AuthRoutes{handler: handler, cfg: cfg, responder: responder}
}

// Version implements router.Versioned; internal routes are not versioned.
func (r *AuthRoutes) Version() string {
	return ""
}

// Register implements router.Routes; every request is rejected while AUTH_INTERNAL_SECRET is unset.
func (r *AuthRoutes) Register(group *gin.RouterGroup) {
	items := group.Group("/internal/auth", middleware.RequireSecret(internalSecretHeader, r.cfg.Auth.InternalSecret, r.responder))

	items.POST("/token-details", r.handler.TokenDetails)
	items.POST("/revoke", r.handler.Revoke)
	items.POST("/revoke-all", r.handler.RevokeAll)
}
