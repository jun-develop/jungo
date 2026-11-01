package middleware

import (
	"context"
	"fmt"
	"net/http"
	"reflect"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/jun-develop/junkit/response"
	"github.com/jun-develop/junkit/security"

	"jungo/internal/common/actor"
)

// PermissionLoader resolves permissions; implemented by the access feature.
type PermissionLoader interface {
	Permissions(ctx context.Context, userID int64) ([]string, error)
	IsPermission(code string) bool
}

// Subject is the authenticated identity Guard reads; implemented by auth's Identity.
type Subject interface {
	SubjectID() int64
	SubjectUUID() uuid.UUID
}

// PermissionCarrier is a Subject that may already hold its permission codes, read in the same query
// as its session; ok false means Guard loads them through PermissionLoader.
type PermissionCarrier interface {
	Permissions() (codes []string, ok bool)
}

// Guard wraps route handlers with a permission policy. Every route under a versioned API group
// must be wrapped by Can, Authenticated or Public (enforced by router.RegisterAll via Guards).
//
// Usage:
//
//	users.POST("", r.guard.Can(r.handler.CreateUser, domain.UsersCreate))
//	users.GET("/:uuid", r.guard.Authenticated(r.handler.GetUser))
type Guard struct {
	loader    PermissionLoader
	responder response.Responder

	// wrapped holds the code pointer of every handler Guard returned. Written only while routes
	// register at startup; read by Guards afterwards.
	wrapped map[uintptr]bool
}

// NewGuard creates a Guard.
func NewGuard(loader PermissionLoader, responder response.Responder) *Guard {
	return &Guard{loader: loader, responder: responder, wrapped: make(map[uintptr]bool)}
}

// Can allows the request when the identity holds every permission in perms. It panics at route
// registration on an empty or unknown permission, so a typo cannot lock or open a route silently.
func (g *Guard) Can(h gin.HandlerFunc, perms ...string) gin.HandlerFunc {
	if len(perms) == 0 {
		panic("middleware: Guard.Can needs at least one permission")
	}

	for _, p := range perms {
		if !g.loader.IsPermission(p) {
			panic(fmt.Sprintf("middleware: Guard.Can: unknown permission %q (add it to the Permissions list in its feature's domain/permission.go)", p))
		}
	}

	return g.mark(func(c *gin.Context) {
		a, ok := g.actor(c)
		if !ok {
			return
		}

		for _, p := range perms {
			if !a.Has(p) {
				g.responder.Error(c, actor.ErrForbidden)
				c.Abort()

				return
			}
		}

		h(c)
	})
}

// Authenticated allows any authenticated identity; the service checks ownership via
// actor.RequireSelfOrPermission.
func (g *Guard) Authenticated(h gin.HandlerFunc) gin.HandlerFunc {
	return g.mark(func(c *gin.Context) {
		if _, ok := g.actor(c); ok {
			h(c)
		}
	})
}

// Public marks a route that needs no authentication.
func (g *Guard) Public(h gin.HandlerFunc) gin.HandlerFunc {
	return g.mark(func(c *gin.Context) {
		h(c)
	})
}

// actor loads the identity's permissions and stores the Actor in the request context. It answers
// the request itself and returns false when that fails.
func (g *Guard) actor(c *gin.Context) (*actor.Actor, bool) {
	subject, ok := security.GetIdentity[Subject](c)
	if !ok {
		// The route is missing BearerAuth; fail closed.
		g.responder.Send(c, http.StatusUnauthorized, "unauthorized_token")
		c.Abort()

		return nil, false
	}

	perms, err := g.permissions(c.Request.Context(), subject)
	if err != nil {
		g.responder.Error(c, err)
		c.Abort()

		return nil, false
	}

	a := &actor.Actor{UserID: subject.SubjectID(), UserUUID: subject.SubjectUUID(), Permissions: perms}
	c.Request = c.Request.WithContext(actor.With(c.Request.Context(), a))

	return a, true
}

// permissions returns the codes the subject already carries, or loads them.
func (g *Guard) permissions(ctx context.Context, subject Subject) ([]string, error) {
	if carrier, ok := subject.(PermissionCarrier); ok {
		if codes, ok := carrier.Permissions(); ok {
			return codes, nil
		}
	}

	return g.loader.Permissions(ctx, subject.SubjectID())
}

// Guards reports whether h (gin.RouteInfo.HandlerFunc) was returned by Can, Authenticated or Public.
func (g *Guard) Guards(h gin.HandlerFunc) bool {
	return g.wrapped[reflect.ValueOf(h).Pointer()]
}

// mark records h as a Guard handler. Every closure built from one func literal shares its code
// pointer, so the map ends up with one key per wrapper (Can, Authenticated, Public); a handler not
// returned by Guard has another pointer. permission_test.go checks this still holds.
func (g *Guard) mark(h gin.HandlerFunc) gin.HandlerFunc {
	g.wrapped[reflect.ValueOf(h).Pointer()] = true
	return h
}
