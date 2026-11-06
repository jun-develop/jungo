package infrastructure

import (
	"context"
	"fmt"
	"strings"
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

	CacheOptions cache.Options
	Config       *config.Config
	Logger       *zap.Logger
	Telegram     telegram.Client `optional:"true"`
}

// LoginGuard implements domain.LoginGuard with fixed-window counters per IP (short window and
// blacklist window) and per email. The short-window and email counters count every attempt up
// front and are cleared on success; the blacklist counter counts failures only.
type LoginGuard struct {
	counters cache.Cache[int64]
	cfg      config.AuthConfig
	chatID   string
	env      string
	logger   *zap.Logger
	telegram telegram.Client
}

// NewLoginGuard creates a LoginGuard; it counts in memory when Redis is disabled.
func NewLoginGuard(p LoginGuardParams) *LoginGuard {
	return &LoginGuard{
		counters: cache.New[int64](p.CacheOptions.OrMemory()),
		cfg:      p.Config.Auth,
		chatID:   p.Config.Telegram.ChatID,
		env:      p.Config.Environment,
		logger:   p.Logger,
		telegram: p.Telegram,
	}
}

// Attempt implements domain.LoginGuard; it returns ErrIPBlocked or ErrTooManyAttempts when blocked.
// The email is checked first, so a blocked email does not use up the IP's attempts. A cache error
// refuses the attempt, so an outage cannot turn throttling off.
func (g *LoginGuard) Attempt(ctx context.Context, ip, email string) (int64, error) {
	if n, _ := g.counters.Get(ctx, ipLongKey(ip)); n >= g.cfg.LoginBlacklistAttempts {
		return 0, domain.ErrIPBlocked
	}

	perEmail, err := g.incr(ctx, emailKey(email), g.cfg.LoginBlockWindow)
	if err != nil {
		return 0, err
	}

	if perEmail > g.cfg.LoginEmailMaxAttempts {
		return 0, domain.ErrTooManyAttempts
	}

	short, err := g.incr(ctx, ipShortKey(ip), g.cfg.LoginBlockWindow)
	if err != nil {
		return 0, err
	}

	if short > g.cfg.LoginMaxAttempts {
		return 0, domain.ErrTooManyAttempts
	}

	return g.cfg.LoginMaxAttempts - short, nil
}

// RecordFailure implements domain.LoginGuard; it counts the failure towards the IP blacklist.
func (g *LoginGuard) RecordFailure(ctx context.Context, ip string) {
	long, err := g.incr(ctx, ipLongKey(ip), g.cfg.LoginBlacklistWindow)
	if err != nil {
		return
	}

	if long == g.cfg.LoginBlacklistAttempts {
		g.logger.Warn("login guard: IP blacklisted after repeated failures", zap.String("ip", ip), zap.String("blocked", security.ClientKey(ip)), zap.Int64("failures", long))
		g.notifyBlacklisted(ctx, ip, long)
	}
}

// Succeeded implements domain.LoginGuard; it clears the short-window counters but keeps the
// blacklist counter, so logging into an attacker-owned account cannot reset it.
func (g *LoginGuard) Succeeded(ctx context.Context, ip, email string) {
	_ = g.counters.Delete(ctx, ipShortKey(ip))
	_ = g.counters.Delete(ctx, emailKey(email))
}

// AttemptPasswordReset implements domain.LoginGuard; it counts every request per IP, then per
// email whether or not the email is registered, and returns ErrTooManyResetRequests over either
// limit. This caps the emails one client can make us send. A cache error refuses the request.
func (g *LoginGuard) AttemptPasswordReset(ctx context.Context, ip, email string) error {
	perIP, err := g.incr(ctx, "auth:reset:ip:"+security.ClientKey(ip), g.cfg.PasswordResetWindow)
	if err != nil {
		return err
	}

	if perIP > g.cfg.PasswordResetIPMax {
		return domain.ErrTooManyResetRequests
	}

	perEmail, err := g.incr(ctx, "auth:reset:email:"+hashEmail(email), g.cfg.PasswordResetWindow)
	if err != nil {
		return err
	}

	if perEmail > g.cfg.PasswordResetEmailMax {
		return domain.ErrTooManyResetRequests
	}

	return nil
}

// incr increments a counter, logging a failure.
func (g *LoginGuard) incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	n, err := g.counters.Incr(ctx, key, ttl)
	if err != nil {
		g.logger.Error("login guard: increment counter failed", zap.String("key", key), zap.Error(err))
		return 0, fmt.Errorf("increment login counter: %w", err)
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

	go func() {
		sendCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), notifyTimeout)
		defer cancel()
		if err := g.telegram.SendMessage(sendCtx, g.chatID, msg); err != nil {
			g.logger.Error("login guard: telegram alert failed", zap.Error(err))
		}
	}()
}

// ipShortKey returns the short-window counter key for ip.
func ipShortKey(ip string) string {
	return "auth:login:ip:short:" + security.ClientKey(ip)
}

// ipLongKey returns the long-window counter key for ip.
func ipLongKey(ip string) string {
	return "auth:login:ip:long:" + security.ClientKey(ip)
}

// emailKey returns the counter key for email (hashed, so addresses are not stored).
func emailKey(email string) string {
	return "auth:login:email:" + hashEmail(email)
}

// hashEmail returns a normalized, hashed email for counter keys, so addresses are not stored.
func hashEmail(email string) string {
	return security.HashToken(strings.ToLower(strings.TrimSpace(email)))
}
