package infrastructure

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/fx"
	"go.uber.org/zap"

	"github.com/jun-develop/junkit/cache"
	"github.com/jun-develop/junkit/security"
	"github.com/jun-develop/junkit/telegram"

	"jungo/internal/config"
	"jungo/internal/features/auth/domain"
)

// notifyTimeout bounds the blacklist Telegram alert.
const notifyTimeout = 5 * time.Second

// LoginGuardParams defines dependencies for LoginGuard.
type LoginGuardParams struct {
	fx.In

	Lifecycle fx.Lifecycle
	Cache     *cache.Store
	Config    *config.Config
	Logger    *zap.Logger
	Telegram  telegram.Client `optional:"true"`
}

// LoginGuard implements domain.LoginGuard with fixed-window counters per client IP: a short-window
// counter of every attempt, cleared on success, and a blacklist counter of failures only. Logins
// are not counted per email: anyone could then lock any account out by failing on purpose.
type LoginGuard struct {
	counters cache.Cache[int64]
	cfg      config.AuthConfig
	chatID   string
	env      string
	logger   *zap.Logger
	telegram telegram.Client

	// alerts tracks Telegram alerts still sending, so shutdown waits for them.
	alerts sync.WaitGroup
}

// NewLoginGuard creates a LoginGuard; it counts in memory when Redis is disabled.
func NewLoginGuard(p LoginGuardParams) *LoginGuard {
	g := &LoginGuard{
		counters: cache.New[int64](p.Cache.OrMemory()),
		cfg:      p.Config.Auth,
		chatID:   p.Config.Telegram.ChatID,
		env:      p.Config.Environment,
		logger:   p.Logger,
		telegram: p.Telegram,
	}

	p.Lifecycle.Append(fx.StopHook(func(ctx context.Context) error {
		return waitOrTimeout(ctx, &g.alerts)
	}))

	return g
}

// Attempt implements domain.LoginGuard; it returns ErrIPBlocked or ErrTooManyAttempts when blocked.
// A cache error refuses the attempt, so an outage cannot turn throttling off.
func (g *LoginGuard) Attempt(ctx context.Context, ip string) (int64, error) {
	if failures, _ := g.counters.Get(ctx, ipBlacklistKey(ip)); failures >= g.cfg.LoginBlacklistAttempts {
		return 0, domain.ErrIPBlocked
	}

	attempts, err := g.incr(ctx, ipAttemptsKey(ip), g.cfg.LoginBlockWindow)
	if err != nil {
		return 0, err
	}

	if attempts > g.cfg.LoginMaxAttempts {
		return 0, domain.ErrTooManyAttempts
	}

	return g.cfg.LoginMaxAttempts - attempts, nil
}

// RecordFailure implements domain.LoginGuard; it counts the failure towards the IP blacklist.
func (g *LoginGuard) RecordFailure(ctx context.Context, ip string) {
	failures, err := g.incr(ctx, ipBlacklistKey(ip), g.cfg.LoginBlacklistWindow)
	if err != nil {
		return
	}

	if failures == g.cfg.LoginBlacklistAttempts {
		g.logger.Warn("login guard: IP blacklisted after repeated failures",
			zap.String("ip", ip),
			zap.String("blocked", security.ClientKey(ip)),
			zap.Int64("failures", failures),
		)
		g.notifyBlacklisted(ctx, ip, failures)
	}
}

// RecordSuccess implements domain.LoginGuard; it clears the short-window counter but keeps the
// blacklist counter, so logging into an attacker-owned account cannot reset it.
func (g *LoginGuard) RecordSuccess(ctx context.Context, ip string) {
	if err := g.counters.Delete(ctx, ipAttemptsKey(ip)); err != nil {
		g.logger.Warn("login guard: clear attempts failed", zap.Error(err))
	}
}

// AttemptPasswordReset implements domain.LoginGuard; it counts every request per IP, then per
// email whether or not the email is registered, and returns ErrTooManyResetRequests over either
// limit. This caps the emails one client can make us send. A cache error refuses the request.
func (g *LoginGuard) AttemptPasswordReset(ctx context.Context, ip, email string) error {
	perIP, err := g.incr(ctx, resetIPKey(ip), g.cfg.PasswordResetWindow)
	if err != nil {
		return err
	}

	if perIP > g.cfg.PasswordResetIPMax {
		return domain.ErrTooManyResetRequests
	}

	perEmail, err := g.incr(ctx, resetEmailKey(email), g.cfg.PasswordResetWindow)
	if err != nil {
		return err
	}

	if perEmail > g.cfg.PasswordResetEmailMax {
		return domain.ErrTooManyResetRequests
	}

	return nil
}

// incr increments a counter; the caller returns the error, which the access log records.
func (g *LoginGuard) incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	n, err := g.counters.Incr(ctx, key, ttl)
	if err != nil {
		return 0, fmt.Errorf("login guard: increment %s: %w", key, err)
	}

	return n, nil
}

// notifyBlacklisted sends a best-effort Telegram alert when Telegram is configured.
func (g *LoginGuard) notifyBlacklisted(ctx context.Context, ip string, failures int64) {
	if g.telegram == nil || g.chatID == "" {
		return
	}

	msg := fmt.Sprintf("🛡️ <b>Security Alert: Brute Force Attempt</b>\n"+
		"<b>Environment:</b> %s\n"+
		"<b>IP Address:</b> <code>%s</code> (blocked: <code>%s</code>)\n"+
		"<b>Time:</b> %s\n"+
		"⛔ <b>Action:</b> IP blocked for <b>%s</b> (%d failed attempts).",
		g.env, ip, security.ClientKey(ip), time.Now().Format(time.DateTime), g.cfg.LoginBlacklistWindow, failures)

	g.alerts.Go(func() {
		sendCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), notifyTimeout)
		defer cancel()

		if err := g.telegram.SendMessage(sendCtx, g.chatID, msg); err != nil {
			g.logger.Error("login guard: telegram alert failed", zap.Error(err))
		}
	})
}

// waitOrTimeout waits for wg, or until ctx (Fx's stop timeout) ends.
func waitOrTimeout(ctx context.Context, wg *sync.WaitGroup) error {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ipAttemptsKey returns the short-window attempts counter key for ip.
func ipAttemptsKey(ip string) string {
	return "auth:login:ip:attempts:" + security.ClientKey(ip)
}

// ipBlacklistKey returns the blacklist (failures) counter key for ip.
func ipBlacklistKey(ip string) string {
	return "auth:login:ip:failures:" + security.ClientKey(ip)
}

// resetIPKey returns the password reset counter key for ip.
func resetIPKey(ip string) string {
	return "auth:reset:ip:" + security.ClientKey(ip)
}

// resetEmailKey returns the password reset counter key for email (hashed, so addresses are not
// stored).
func resetEmailKey(email string) string {
	return "auth:reset:email:" + security.HashToken(strings.ToLower(strings.TrimSpace(email)))
}
