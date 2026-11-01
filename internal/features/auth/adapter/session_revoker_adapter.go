package adapter

import (
	"context"

	"github.com/google/uuid"

	authdomain "jungo/internal/features/auth/domain"
)

// SessionRevokerAdapter implements userdomain.SessionRevoker. It uses the repository, not
// AuthService, to avoid a dependency cycle with the user feature.
type SessionRevokerAdapter struct {
	repo  authdomain.AuthRepository
	cache authdomain.SessionCache
}

// NewSessionRevokerAdapter creates a SessionRevokerAdapter.
func NewSessionRevokerAdapter(repo authdomain.AuthRepository, cache authdomain.SessionCache) *SessionRevokerAdapter {
	return &SessionRevokerAdapter{repo: repo, cache: cache}
}

// RevokeUserSessions implements userdomain.SessionRevoker.
func (a *SessionRevokerAdapter) RevokeUserSessions(ctx context.Context, uid uuid.UUID) error {
	families, err := a.repo.RevokeAllForUser(ctx, uid, authdomain.RevokedReasonUserDisabled)
	if err != nil {
		return err
	}

	a.cache.InvalidateFamilies(ctx, families...)

	return nil
}
