package app

import (
	"errors"
	"fmt"
	"os"

	"github.com/gin-gonic/gin"
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/jun-develop/junkit/cache"
	"github.com/jun-develop/junkit/httpclient"
	"github.com/jun-develop/junkit/i18n"
	"github.com/jun-develop/junkit/logger"
	"github.com/jun-develop/junkit/mailer"
	"github.com/jun-develop/junkit/notification"
	"github.com/jun-develop/junkit/recaptcha"
	"github.com/jun-develop/junkit/response"
	"github.com/jun-develop/junkit/security"
	"github.com/jun-develop/junkit/storage"
	"github.com/jun-develop/junkit/telegram"
	"github.com/jun-develop/junkit/validation"

	"jungo/internal/config"
	"jungo/internal/console"
	"jungo/internal/console/commands"
	"jungo/internal/database/primary"
	"jungo/internal/features/access"
	"jungo/internal/features/auth"
	"jungo/internal/features/user"
	"jungo/internal/router"
)

// CoreModules returns Fx options shared between the API server and console.
func CoreModules(cfg *config.Config) []fx.Option {
	return []fx.Option{
		// Route Fx event logs through Zap at Debug level.
		fx.WithLogger(func(log *zap.Logger) fxevent.Logger {
			zlog := &fxevent.ZapLogger{Logger: log}
			zlog.UseLogLevel(zapcore.DebugLevel)

			return zlog
		}),

		// =====================================================================
		// CONFIG
		// =====================================================================
		fx.Supply(cfg),

		// =====================================================================
		// CORE PACKAGES (github.com/jun-develop/junkit)
		// =====================================================================
		fx.Options(provideLoggers(cfg)...),

		fx.Module("database",
			fx.Decorate(fx.Annotate(
				func(sqlLogger *zap.Logger) *zap.Logger { return sqlLogger },
				fx.ParamTags(`name:"sql"`),
			)),
			primary.Module,
		),

		fx.Provide(provideResponseOptions),
		i18n.Module,
		response.Module,

		fx.Provide(provideValidationOptions),
		validation.Module,

		fx.Provide(provideSecurityOptions),
		security.Module,

		// =====================================================================
		// OPTIONAL MODULES & INTEGRATIONS
		// =====================================================================
		fx.Provide(provideCacheOptions),
		cache.Module,

		fx.Provide(provideStorageOptions),
		storage.Module,

		fx.Provide(httpclient.NewDefaultClient),

		fx.Provide(provideTelegramOptions),
		telegram.Module,

		fx.Provide(provideNotificationOptions),
		notification.Module,

		fx.Provide(provideRecaptchaOptions),
		recaptcha.Module,

		fx.Provide(provideMailerOptions),
		mailer.Module,

		// =====================================================================
		// FEATURES
		// =====================================================================
		access.Module,
		auth.Module,
		user.Module,

		// =====================================================================
		// GLOBAL CONSOLE COMMANDS
		// =====================================================================
		commands.Module,
	}
}

// HTTPModules returns Fx options for the HTTP server lifecycle and routing.
func HTTPModules() []fx.Option {
	return []fx.Option{
		fx.Provide(provideGin),

		fx.Provide(router.Module),
		fx.Invoke(router.RegisterAll),

		fx.Provide(NewApp),
		fx.Invoke((*App).Run),
	}
}

// GetFxOptions returns all Fx options configured for the API server.
func GetFxOptions(cfg *config.Config) []fx.Option {
	return append(CoreModules(cfg), HTTPModules()...)
}

// NewAPIFx initializes and assembles the full API server Fx application.
func NewAPIFx() *fx.App {
	cfg := config.NewConfig()
	return fx.New(GetFxOptions(cfg)...)
}

// NewConsoleFx assembles the Fx application for running a single CLI command. Logs go to files
// only; --verbose prints app logs and executed SQL, --debug prints everything (Fx events too).
func NewConsoleFx() *fx.App {
	cfg := config.NewConfig()
	verbose, debug := consoleFlags()

	opts := []fx.Option{
		fx.Provide(console.Module),
		fx.Invoke(console.RunSelected),
	}

	switch {
	case debug:
		cfg.Logger.Output = logger.OutputConsole
		cfg.Logger.AppLevel, cfg.Logger.SQLLevel = "debug", "debug"
		cfg.DB.QueryLogging = true
	case verbose:
		cfg.Logger.Output = logger.OutputConsole
		cfg.Logger.AppLevel, cfg.Logger.SQLLevel = "info", "info"
		cfg.DB.QueryLogging = true
		opts = append(opts, fxErrorsOnly())
	default:
		cfg.Logger.Output = logger.OutputFile
		opts = append(opts, fxErrorsOnly())
	}

	return fx.New(append(CoreModules(cfg), opts...)...)
}

// consoleFlags strips --verbose/--debug from os.Args so commands never receive them.
func consoleFlags() (verbose, debug bool) {
	args := []string{os.Args[0]}
	for _, a := range os.Args[1:] {
		switch a {
		case "--verbose":
			verbose = true
		case "--debug":
			debug = true
		default:
			args = append(args, a)
		}
	}

	os.Args = args

	return verbose, debug
}

// fxErrorsOnly replaces CoreModules' Fx logger (the last WithLogger wins) with one that prints
// only failures to stderr, so a startup error such as an unreachable database is never silent.
func fxErrorsOnly() fx.Option {
	return fx.WithLogger(func() fxevent.Logger {
		enc := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
		return &fxevent.ZapLogger{Logger: zap.New(zapcore.NewCore(enc, zapcore.Lock(os.Stderr), zapcore.ErrorLevel))}
	})
}

// provideGin initializes the Gin engine with trusted proxies
func provideGin(cfg *config.Config) (*gin.Engine, error) {
	r := gin.New()
	if err := r.SetTrustedProxies(cfg.Security.TrustedProxies); err != nil {
		return nil, fmt.Errorf("SECURITY_TRUSTED_PROXIES: %w", err)
	}

	return r, nil
}

// provideLoggers builds the app/http/sql/limiter named logging channels.
func provideLoggers(cfg *config.Config) []fx.Option {
	shared := logger.Options{
		Environment: cfg.Environment,
		Output:      cfg.Logger.Output,
		MaxSize:     cfg.Logger.MaxSize,
		MaxBackups:  cfg.Logger.MaxBackups,
		MaxAge:      cfg.Logger.MaxAge,
		Compress:    cfg.Logger.Compress,
	}

	defs := []logger.Definition{
		{Name: "app", Level: cfg.Logger.AppLevel, Filename: cfg.Logger.AppFilename},
		{Name: "http", Level: cfg.Logger.HTTPLevel, Filename: cfg.Logger.HTTPFilename},
		{Name: "sql", Level: cfg.Logger.SQLLevel, Filename: cfg.Logger.SQLFilename},
		{Name: "limiter", Level: cfg.Logger.LimiterLevel, Filename: cfg.Logger.LimiterFilename},
	}

	return logger.ProvideNamed(defs, shared)
}

// provideResponseOptions builds response.Options from cfg.
func provideResponseOptions(cfg *config.Config) response.Options {
	return response.Options{Language: cfg.Language}
}

// provideValidationOptions builds validation.Options from cfg.
func provideValidationOptions(cfg *config.Config) validation.Options {
	return validation.Options{Language: cfg.Language}
}

// provideSecurityOptions builds security.Options from cfg.Auth; development falls back
// to random keys.
func provideSecurityOptions(cfg *config.Config, log *zap.Logger) (security.Options, error) {
	opts := security.Options{Password: security.PasswordOptions{Cost: cfg.Auth.PasswordCost}}

	if cfg.IsDevelopment() && cfg.Auth.TokenHMACSecret == "" && cfg.Auth.TokenEncryptionKey == "" {
		log.Warn("security: AUTH_TOKEN_HMAC_SECRET / AUTH_TOKEN_ENCRYPTION_KEY not set, using random keys; tokens will not survive a restart")
		opts.TokenHMACSecret = security.RandomBytes(security.MinHMACSecretSize)
		opts.TokenEncryptionKey = security.RandomBytes(security.EncryptionKeySize)

		return opts, nil
	}

	var err error
	if opts.TokenHMACSecret, err = security.DecodeKey(cfg.Auth.TokenHMACSecret); err != nil {
		return security.Options{}, fmt.Errorf("AUTH_TOKEN_HMAC_SECRET: %w", err)
	}

	if opts.TokenEncryptionKey, err = security.DecodeKey(cfg.Auth.TokenEncryptionKey); err != nil {
		return security.Options{}, fmt.Errorf("AUTH_TOKEN_ENCRYPTION_KEY: %w", err)
	}

	return opts, nil
}

// provideCacheOptions uses Redis when enabled, otherwise no cache, because an in-memory cache
// would let other instances keep serving revoked sessions and permissions.
func provideCacheOptions(cfg *config.Config) cache.Options {
	if !cfg.Redis.Enabled {
		return cache.Options{Driver: cache.DriverNoop}
	}

	return cache.Options{
		Driver: cache.DriverRedis,
		Redis: cache.RedisOptions{
			Addr:     cfg.Redis.Host + ":" + cfg.Redis.Port,
			Password: cfg.Redis.Password,
			DB:       cfg.Redis.DB,
		},
	}
}

// provideStorageOptions builds storage.Options from cfg.Storage.
func provideStorageOptions(cfg *config.Config) storage.Options {
	return storage.Options{BaseDir: cfg.Storage.BaseDir, BaseURL: cfg.Storage.BaseURL}
}

// provideTelegramOptions builds telegram.Options from cfg.Telegram.
func provideTelegramOptions(cfg *config.Config) telegram.Options {
	return telegram.Options{Token: cfg.Telegram.Token}
}

// provideNotificationOptions routes notifications to the configured Telegram chat.
func provideNotificationOptions(cfg *config.Config) notification.Options {
	return notification.Options{TelegramChatID: cfg.Telegram.ChatID, Environment: cfg.Environment}
}

// provideMailerOptions builds mailer.Options from cfg.Mail; warns when the log driver runs outside development.
func provideMailerOptions(cfg *config.Config, log *zap.Logger) mailer.Options {
	m := cfg.Mail
	if !cfg.IsDevelopment() && (m.Driver == "" || m.Driver == string(mailer.DriverLog)) {
		log.Warn("mailer: MAIL_DRIVER=log outside development; emails are logged, not sent")
	}

	return mailer.Options{
		Driver: mailer.Driver(m.Driver),
		From:   m.From,
		SMTP: mailer.SMTPOptions{
			Host:     m.SMTPHost,
			Port:     m.SMTPPort,
			Username: m.SMTPUsername,
			Password: m.SMTPPassword,
		},
		Brevo: mailer.BrevoOptions{APIKey: m.BrevoAPIKey},
	}
}

// provideRecaptchaOptions builds recaptcha.Options from cfg.Recaptcha; the mock is used only in
// development.
func provideRecaptchaOptions(cfg *config.Config) (recaptcha.Options, error) {
	dev := cfg.IsDevelopment()
	if !dev && cfg.Auth.RecaptchaOnLogin && cfg.Recaptcha.SecretKey == "" {
		return recaptcha.Options{}, errors.New("RECAPTCHA_SECRET_KEY: required outside development when AUTH_RECAPTCHA_ON_LOGIN=true")
	}

	return recaptcha.Options{
		SecretKey: cfg.Recaptcha.SecretKey,
		MinScore:  cfg.Recaptcha.MinScore,
		Mock:      cfg.Recaptcha.Mock && dev,
	}, nil
}
