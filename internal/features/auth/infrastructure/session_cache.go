package infrastructure

import (
	"context"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/jun-develop/junkit/cache"

	"jungo/internal/config"
	"jungo/internal/features/auth/domain"
)

// SessionCache implements domain.SessionCache on a cache.Invalidatable whose marker is the
// session's family: invalidating a family makes every cached session of it a miss.
type SessionCache struct {
	sessions *cache.Invalidatable[*domain.Session]
	logger   *zap.Logger
}

// NewSessionCache creates a SessionCache using the app's cache driver.
func NewSessionCache(opts cache.Options, cfg *config.Config, logger *zap.Logger) *SessionCache {
	return &SessionCache{
		sessions: cache.NewInvalidatable[*domain.Session](opts, cfg.Auth.SessionCacheTTL),
		logger:   logger,
	}
}

// GetOrLoad implements domain.SessionCache; it returns a copy of the cached session, or calls load
// and caches the result on a miss.
func (c *SessionCache) GetOrLoad(ctx context.Context, hash string, load func() (*domain.Session, error)) (*domain.Session, error) {
	session, hit, err := c.sessions.GetOrLoad(ctx, sessionKey(hash), func(s *domain.Session) []string {
		if s == nil {
			return nil
		}

		return []string{familyKey(s.FamilyUUID)}
	}, load)
	if err != nil || !hit || session == nil {
		return session, err
	}

	copied := *session
	// Cached codes could be stale; the Guard reloads them through the permission cache.
	copied.Permissions = nil

	return &copied, nil
}

// InvalidateFamilies implements domain.SessionCache; it marks every cached session of the families
// stale. A missed marker keeps them valid until their TTL.
func (c *SessionCache) InvalidateFamilies(ctx context.Context, familyUUIDs ...uuid.UUID) {
	for _, family := range familyUUIDs {
		if family == uuid.Nil {
			continue
		}

		if err := c.sessions.Invalidate(ctx, familyKey(family)); err != nil {
			c.logger.Error("session cache: invalidate family failed", zap.String("family_uuid", family.String()), zap.Error(err))
		}
	}
}

// sessionKey returns the cache key for the session of a token hash.
func sessionKey(hash string) string {
	return "auth:session:" + hash + ":entry"
}

// familyKey returns the cache key for a family's invalidation marker.
func familyKey(familyUUID uuid.UUID) string {
	return "auth:family:" + familyUUID.String() + ":invalidated_at"
}
