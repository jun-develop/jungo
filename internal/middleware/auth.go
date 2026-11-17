package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	kitmw "github.com/jun-develop/junkit/middleware"
	"github.com/jun-develop/junkit/response"
	"github.com/jun-develop/junkit/security"
)

// Authenticator resolves a bearer token into an identity. Return a *response.AppError
// for token problems; any other error is answered with 500.
type Authenticator[T any] interface {
	Authenticate(ctx context.Context, token string) (T, error)
}

// AuthenticatorFunc adapts a function to Authenticator.
type AuthenticatorFunc[T any] func(ctx context.Context, token string) (T, error)

// Authenticate implements Authenticator.
func (f AuthenticatorFunc[T]) Authenticate(ctx context.Context, token string) (T, error) {
	return f(ctx, token)
}

// InternalSecretHeader carries AUTH_INTERNAL_SECRET on service-to-service calls.
const InternalSecretHeader = "X-Internal-Secret"

// Authenticate is the bearer-token middleware the auth feature provides. Routers depend on this
// type, not on the auth feature, to protect their routes.
//
// Usage:
//
//	users := group.Group("/users", gin.HandlerFunc(r.authenticate))
type Authenticate gin.HandlerFunc

// BearerAuth authenticates "Authorization: Bearer <token>" and stores the identity via
// kitmw.SetIdentity (request context).
//
// Usage:
//
//	auth := middleware.BearerAuth(authenticator, responder)
//	protected := router.Group("", auth)
//	identity := security.MustGetIdentity[*domain.Identity](c) // in handlers
func BearerAuth[T any](a Authenticator[T], responder response.Responder) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, ok := BearerToken(c)
		if !ok {
			responder.Send(c, http.StatusUnauthorized, "unauthorized_token")
			c.Abort()

			return
		}

		identity, err := a.Authenticate(c.Request.Context(), token)
		if err != nil {
			responder.Error(c, err)
			c.Abort()

			return
		}

		kitmw.SetIdentity(c, identity)
		c.Next()
	}
}

// BearerToken extracts the token from an "Authorization: Bearer <token>" header; the scheme is
// case-insensitive.
//
// Usage:
//
//	token, ok := middleware.BearerToken(c)
func BearerToken(c *gin.Context) (string, bool) {
	const prefix = "bearer "
	header := c.GetHeader("Authorization")
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}

	token := strings.TrimSpace(header[len(prefix):])
	if token == "" {
		return "", false
	}

	return token, true
}

// RequireSecret allows requests whose header equals secret; an empty secret denies all requests.
//
// Usage:
//
//	guard := middleware.RequireSecret(middleware.InternalSecretHeader, secret, responder)
//	internal := router.Group("/internal", guard)
func RequireSecret(header, secret string, responder response.Responder) gin.HandlerFunc {
	return func(c *gin.Context) {
		if secret == "" || !security.SecureEqual(c.GetHeader(header), secret) {
			responder.Send(c, http.StatusForbidden, "forbidden_internal_access")
			c.Abort()

			return
		}

		c.Next()
	}
}
