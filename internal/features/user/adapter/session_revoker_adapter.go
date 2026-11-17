package adapter

import (
	"context"

	"github.com/google/uuid"

	authdomain "jungo/internal/features/auth/domain"
)

// SessionRevokerAdapter implements userdomain.SessionRevoker over the auth feature. It uses auth's
// repository and session cache, not AuthService, because AuthService depends on the user feature
// (through domain.CredentialStore): going through it would make an Fx dependency cycle.
type SessionRevokerAdapter struct {
	repo  authdomain.AuthRepository
	cache authdomain.SessionCache
}

// NewSessionRevokerAdapter creates a SessionRevokerAdapter.
func NewSessionRevokerAdapter(repo authdomain.AuthRepository, cache authdomain.SessionCache) *SessionRevokerAdapter {
	return &SessionRevokerAdapter{repo: repo, cache: cache}
}

// RevokeUserSessions implements userdomain.SessionRevoker.
func (a *SessionRevokerAdapter) RevokeUserSessions(ctx context.Context, userUUID uuid.UUID) error {
	_, err := a.repo.RevokeAllForUser(ctx, userUUID, authdomain.RevokedReasonUserDisabled)
	return err
}

// InvalidateUserSessions implements userdomain.SessionRevoker.
func (a *SessionRevokerAdapter) InvalidateUserSessions(ctx context.Context, userUUID uuid.UUID) {
	a.cache.InvalidateUser(ctx, userUUID)
}
