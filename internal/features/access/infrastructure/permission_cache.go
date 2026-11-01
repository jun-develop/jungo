package infrastructure

import (
	"context"
	"slices"
	"strconv"

	"go.uber.org/zap"

	"github.com/jun-develop/junkit/cache"

	"jungo/internal/config"
)

// globalInvalidationKey marks every cached entry stale (a role with many users changed).
const globalInvalidationKey = "access:invalidated_at"

// PermissionCache implements domain.PermissionCache on a cache.Invalidatable: each entry is stale
// after its user's marker or the global one.
type PermissionCache struct {
	entries *cache.Invalidatable[[]string]
	logger  *zap.Logger
}

// NewPermissionCache creates a PermissionCache using the app's cache driver.
func NewPermissionCache(opts cache.Options, cfg *config.Config, logger *zap.Logger) *PermissionCache {
	return &PermissionCache{
		entries: cache.NewInvalidatable[[]string](opts, cfg.Auth.PermissionCacheTTL),
		logger:  logger,
	}
}

// GetOrLoad implements domain.PermissionCache; it returns a copy of the cached codes, or calls load
// and caches the result on a miss. An empty result is cached too: most users hold no role.
func (c *PermissionCache) GetOrLoad(ctx context.Context, userID int64, load func() ([]string, error)) ([]string, error) {
	markers := []string{userInvalidationKey(userID), globalInvalidationKey}
	perms, _, err := c.entries.GetOrLoad(ctx, entryKey(userID), func([]string) []string { return markers }, load)

	return slices.Clone(perms), err
}

// InvalidateUsers implements domain.PermissionCache; it deletes each entry and marks it too, for a
// load still running.
func (c *PermissionCache) InvalidateUsers(ctx context.Context, userIDs ...int64) {
	for _, id := range userIDs {
		if err := c.entries.Delete(ctx, entryKey(id)); err != nil {
			c.logger.Error("permission cache: delete entry failed", zap.Int64("user_id", id), zap.Error(err))
		}

		c.mark(ctx, userInvalidationKey(id))
	}
}

// InvalidateAll implements domain.PermissionCache.
func (c *PermissionCache) InvalidateAll(ctx context.Context) {
	c.mark(ctx, globalInvalidationKey)
}

// mark invalidates marker, logging a failure; a missed marker keeps old permissions until the TTL.
func (c *PermissionCache) mark(ctx context.Context, marker string) {
	if err := c.entries.Invalidate(ctx, marker); err != nil {
		c.logger.Error("permission cache: invalidate failed", zap.String("key", marker), zap.Error(err))
	}
}

// entryKey returns the cache key for a user's permissions.
func entryKey(userID int64) string {
	return "access:user:" + strconv.FormatInt(userID, 10) + ":permissions:entry"
}

// userInvalidationKey returns the cache key for a user's invalidation marker.
func userInvalidationKey(userID int64) string {
	return "access:user:" + strconv.FormatInt(userID, 10) + ":invalidated_at"
}
