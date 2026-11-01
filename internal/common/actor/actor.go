package actor

import (
	"context"
	"slices"

	"github.com/google/uuid"

	"github.com/jun-develop/junkit/response"
)

// ErrForbidden is returned when the actor lacks the permission an action needs.
var ErrForbidden = response.New(response.Forbidden, "insufficient_permission")

// Actor is the authenticated user of a request and the permission codes they hold.
type Actor struct {
	UserID      int64
	UserUUID    uuid.UUID
	Permissions []string
}

// Has reports whether the actor holds permission.
func (a *Actor) Has(permission string) bool {
	return slices.Contains(a.Permissions, permission)
}

// Is reports whether the actor is the user uid.
func (a *Actor) Is(uid uuid.UUID) bool {
	return a.UserUUID == uid
}

// actorKey is the private context key for the Actor.
type actorKey struct{}

// With returns a copy of ctx carrying a.
func With(ctx context.Context, a *Actor) context.Context {
	return context.WithValue(ctx, actorKey{}, a)
}

// From returns the Actor stored in ctx by middleware.Guard.
func From(ctx context.Context) (*Actor, bool) {
	a, ok := ctx.Value(actorKey{}).(*Actor)
	return a, ok && a != nil
}

// RequireSelfOrPermission allows the actor when they are uid or hold permission. A context without
// an actor is denied, so a service method called outside a guarded route fails closed.
func RequireSelfOrPermission(ctx context.Context, uid uuid.UUID, permission string) error {
	a, ok := From(ctx)
	if !ok || (!a.Is(uid) && !a.Has(permission)) {
		return ErrForbidden
	}

	return nil
}

// Covers reports whether held contains every code in codes.
func Covers(held, codes []string) bool {
	for _, code := range codes {
		if !slices.Contains(held, code) {
			return false
		}
	}

	return true
}

// PermissionReader reads a user's permission codes from the database.
type PermissionReader interface {
	GetUserPermissions(ctx context.Context, userID int64) ([]string, error)
}

// Reload re-reads the actor's permissions from the database instead of the cached copy, and returns
// ErrForbidden if ctx has no actor or they no longer hold permission. Use it before granting or
// revoking access.
func Reload(ctx context.Context, r PermissionReader, permission string) ([]string, error) {
	a, ok := From(ctx)
	if !ok {
		return nil, ErrForbidden
	}

	held, err := r.GetUserPermissions(ctx, a.UserID)
	if err != nil {
		return nil, err
	}

	if !slices.Contains(held, permission) {
		return nil, ErrForbidden
	}

	return held, nil
}
