package middleware

import (
	"context"
	"fmt"
	"unsafe"

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

// Guard wraps route handlers with a permission policy. Every route under /api must be wrapped by
// Can, Authenticated, Public or Internal (enforced by router.RegisterAll via Policy).
//
// Usage:
//
//	users.POST("", r.guard.Can(r.handler.CreateUser, domain.UsersCreate))
//	users.GET("/:uuid", r.guard.Authenticated(r.handler.GetUser))
type Guard struct {
	loader    PermissionLoader
	responder response.Responder

	// policies holds the Policy of every handler Guard returned. Written only while routes register
	// at startup; read by Policy afterwards.
	policies map[uintptr]Policy
}

// PolicyKind is how Guard protects a route.
type PolicyKind int

// Policy kinds, one per Guard method.
const (
	PolicyPermission PolicyKind = iota + 1
	PolicyAuthenticated
	PolicyPublic
	PolicyInternal
)

// Policy is how one route is protected: its kind and, for PolicyPermission, the codes it needs.
type Policy struct {
	Kind        PolicyKind
	Permissions []string
}

// NewGuard creates a Guard.
func NewGuard(loader PermissionLoader, responder response.Responder) *Guard {
	return &Guard{loader: loader, responder: responder, policies: make(map[uintptr]Policy)}
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

	return g.mark(Policy{Kind: PolicyPermission, Permissions: perms}, func(c *gin.Context) {
		a, ok := g.loadActor(c)
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
	return g.mark(Policy{Kind: PolicyAuthenticated}, func(c *gin.Context) {
		if _, ok := g.loadActor(c); ok {
			h(c)
		}
	})
}

// Public marks a route that needs no authentication.
func (g *Guard) Public(h gin.HandlerFunc) gin.HandlerFunc {
	return g.mark(Policy{Kind: PolicyPublic}, func(c *gin.Context) {
		h(c)
	})
}

// Internal marks a service-to-service route whose group checks the caller itself (RequireSecret).
func (g *Guard) Internal(h gin.HandlerFunc) gin.HandlerFunc {
	return g.mark(Policy{Kind: PolicyInternal}, func(c *gin.Context) {
		h(c)
	})
}

// loadActor loads the identity's permissions and stores the Actor in the request context. It answers
// the request itself and returns false when that fails.
func (g *Guard) loadActor(c *gin.Context) (*actor.Actor, bool) {
	subject, ok := security.GetIdentity[Subject](c)
	if !ok {
		// The route is missing BearerAuth; fail closed.
		g.responder.Error(c, ErrUnauthorizedToken)
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

// Policy returns how h (gin.RouteInfo.HandlerFunc) is protected; ok is false when h was not
// returned by Can, Authenticated, Public or Internal.
func (g *Guard) Policy(h gin.HandlerFunc) (p Policy, ok bool) {
	p, ok = g.policies[closureID(h)]
	return p, ok
}

// mark records h's policy.
func (g *Guard) mark(p Policy, h gin.HandlerFunc) gin.HandlerFunc {
	g.policies[closureID(h)] = p
	return h
}

// closureID identifies one closure: a func value points to its closure object, allocated per Guard
// call (it captures h), so each route gets its own key. reflect's Pointer would return the code
// pointer, shared by every closure of one func literal.
func closureID(h gin.HandlerFunc) uintptr {
	return *(*uintptr)(unsafe.Pointer(&h))
}
