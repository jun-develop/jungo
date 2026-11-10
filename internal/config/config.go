package config

import (
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/caarlos0/env/v11"
)

// DatabaseConfig configures the PostgreSQL connection pool.
type DatabaseConfig struct {
	Host               string        `env:"DB_HOST" envDefault:"localhost"`
	Port               string        `env:"DB_PORT" envDefault:"5432"`
	User               string        `env:"DB_USER" envDefault:"postgres"`
	Password           string        `env:"DB_PASSWORD" envDefault:"postgres"`
	Name               string        `env:"DB_NAME" envDefault:"postgres"`
	SSLMode            string        `env:"DB_SSLMODE" envDefault:"disable"`
	MaxConnection      int32         `env:"DB_MAX_CONNECTION" envDefault:"25"`
	MinConnection      int32         `env:"DB_MIN_CONNECTION" envDefault:"5"`
	MaxConnLifetime    time.Duration `env:"DB_MAX_CONN_LIFETIME" envDefault:"30m"`
	MaxConnIdleTime    time.Duration `env:"DB_MAX_CONN_IDLE_TIME" envDefault:"10m"`
	HealthCheckPeriod  time.Duration `env:"DB_HEALTH_CHECK_PERIOD" envDefault:"1m"`
	SlowQueryThreshold time.Duration `env:"DB_SLOW_QUERY_THRESHOLD" envDefault:"200ms"`
	QueryLogging       bool          `env:"DB_QUERY_LOGGING" envDefault:"false"`
}

// CORSConfig configures cross-origin request handling.
type CORSConfig struct {
	AllowOrigins     []string `env:"CORS_ALLOW_ORIGINS" envDefault:"*"`
	AllowMethods     []string `env:"CORS_ALLOW_METHODS" envDefault:"GET,POST,PUT,PATCH,DELETE,OPTIONS"`
	AllowHeaders     []string `env:"CORS_ALLOW_HEADERS" envDefault:"Content-Type,Authorization,X-Device-ID"`
	AllowCredentials bool     `env:"CORS_ALLOW_CREDENTIALS" envDefault:"false"`
	MaxAge           int      `env:"CORS_MAX_AGE" envDefault:"86400"`
}

// LoggerConfig configures application logging.
type LoggerConfig struct {
	MaxSize    int  `env:"LOG_MAX_SIZE" envDefault:"10"`
	MaxBackups int  `env:"LOG_MAX_BACKUPS" envDefault:"5"`
	MaxAge     int  `env:"LOG_MAX_AGE" envDefault:"7"`
	Compress   bool `env:"LOG_COMPRESS" envDefault:"true"`

	AppLevel string `env:"LOG_APP_LEVEL" envDefault:"info"`

	HTTPLevel string `env:"LOG_HTTP_LEVEL" envDefault:"info"`

	SQLLevel string `env:"LOG_SQL_LEVEL" envDefault:"info"`

	LimiterLevel string `env:"LOG_LIMITER_LEVEL" envDefault:"info"`

	// Output forces logger.OutputConsole or logger.OutputFile; set by the console, not from env.
	Output string
}

// LimiterConfig configures rate limiting.
type LimiterConfig struct {
	RequestsPerSecond int           `env:"LIMITER_RPS" envDefault:"10"`
	Burst             int           `env:"LIMITER_BURST" envDefault:"30"`
	NumShards         int           `env:"LIMITER_SHARDS" envDefault:"64"`
	CleanupInterval   time.Duration `env:"LIMITER_CLEANUP_INTERVAL" envDefault:"1m"`
	ClientTTL         time.Duration `env:"LIMITER_CLIENT_TTL" envDefault:"3m"`
	LogTTL            time.Duration `env:"LIMITER_LOG_TTL" envDefault:"30s"`
	IPWhitelist       []string      `env:"LIMITER_IP_WHITELIST"`
}

// BannerConfig configures banning clients that probe the API; LIMITER_IP_WHITELIST is never banned.
type BannerConfig struct {
	Enabled      bool            `env:"BANNER_ENABLED" envDefault:"true"`
	MaxStrikes   int64           `env:"BANNER_MAX_STRIKES" envDefault:"30"`
	StrikeWindow time.Duration   `env:"BANNER_STRIKE_WINDOW" envDefault:"1m"`
	BanDurations []time.Duration `env:"BANNER_BAN_DURATIONS" envDefault:"15m,1h,24h"`
}

// SecurityConfig configures request security limits and trusted proxies.
type SecurityConfig struct {
	MaxRequestBodySize int64    `env:"SECURITY_MAX_BODY_SIZE" envDefault:"2097152"`
	TrustedProxies     []string `env:"SECURITY_TRUSTED_PROXIES"`
}

// RedisConfig configures the Redis cache connection.
type RedisConfig struct {
	Enabled  bool   `env:"CACHE_REDIS_ENABLE" envDefault:"false"`
	Host     string `env:"REDIS_HOST" envDefault:"localhost"`
	Port     string `env:"REDIS_PORT" envDefault:"6379"`
	Password string `env:"REDIS_PASSWORD"`
	DB       int    `env:"REDIS_DB" envDefault:"0"`
}

// StorageConfig configures the public URL of uploads (files live in StoragePath("uploads")).
// An empty BaseURL follows API_SERVER_PORT (http://localhost:<port>/uploads).
type StorageConfig struct {
	BaseURL string `env:"STORAGE_BASE_URL"`
}

// TelegramConfig configures Telegram notification settings.
type TelegramConfig struct {
	Token  string `env:"TELEGRAM_BOT_TOKEN"`
	ChatID string `env:"TELEGRAM_CHAT_ID"`
}

// MailConfig configures outgoing email. Driver is smtp, brevo or log (logs instead of sending).
type MailConfig struct {
	Driver       string `env:"MAIL_DRIVER" envDefault:"log"`
	From         string `env:"MAIL_FROM"`
	SMTPHost     string `env:"MAIL_SMTP_HOST"`
	SMTPPort     int    `env:"MAIL_SMTP_PORT" envDefault:"587"`
	SMTPUsername string `env:"MAIL_SMTP_USERNAME"`
	SMTPPassword string `env:"MAIL_SMTP_PASSWORD"`
	BrevoAPIKey  string `env:"MAIL_BREVO_API_KEY"`
}

// RecaptchaConfig configures Google reCAPTCHA verification.
type RecaptchaConfig struct {
	SecretKey string  `env:"RECAPTCHA_SECRET_KEY"`
	MinScore  float64 `env:"RECAPTCHA_MIN_SCORE" envDefault:"0.5"`
	Mock      bool    `env:"RECAPTCHA_MOCK" envDefault:"true"`
}

// AuthConfig configures token authentication. Token keys are base64 (`openssl rand -base64 32`);
// changing either key invalidates every issued token.
type AuthConfig struct {
	TokenHMACSecret    string `env:"AUTH_TOKEN_HMAC_SECRET"`
	TokenEncryptionKey string `env:"AUTH_TOKEN_ENCRYPTION_KEY"`

	AccessTokenTTL  time.Duration `env:"AUTH_ACCESS_TOKEN_TTL" envDefault:"15m"`
	RefreshTokenTTL time.Duration `env:"AUTH_REFRESH_TOKEN_TTL" envDefault:"720h"`
	SessionCacheTTL time.Duration `env:"AUTH_SESSION_CACHE_TTL" envDefault:"3m"`

	PermissionCacheTTL time.Duration `env:"AUTH_PERMISSION_CACHE_TTL" envDefault:"60s"`

	RevokedRetention time.Duration `env:"AUTH_REVOKED_RETENTION" envDefault:"168h"`
	InternalSecret   string        `env:"AUTH_INTERNAL_SECRET"`

	PasswordCost     int  `env:"AUTH_PASSWORD_COST" envDefault:"10"`
	RecaptchaOnLogin bool `env:"AUTH_RECAPTCHA_ON_LOGIN" envDefault:"false"`

	LoginMaxAttempts       int64         `env:"AUTH_LOGIN_MAX_ATTEMPTS" envDefault:"5"`
	LoginBlockWindow       time.Duration `env:"AUTH_LOGIN_BLOCK_WINDOW" envDefault:"15m"`
	LoginBlacklistAttempts int64         `env:"AUTH_LOGIN_BLACKLIST_ATTEMPTS" envDefault:"8"`
	LoginBlacklistWindow   time.Duration `env:"AUTH_LOGIN_BLACKLIST_WINDOW" envDefault:"24h"`
	LoginEmailMaxAttempts  int64         `env:"AUTH_LOGIN_EMAIL_MAX_ATTEMPTS" envDefault:"10"`

	PasswordResetURL      string        `env:"AUTH_PASSWORD_RESET_URL"`
	PasswordResetTTL      time.Duration `env:"AUTH_PASSWORD_RESET_TTL" envDefault:"30m"`
	PasswordResetWindow   time.Duration `env:"AUTH_PASSWORD_RESET_WINDOW" envDefault:"1h"`
	PasswordResetIPMax    int64         `env:"AUTH_PASSWORD_RESET_IP_MAX" envDefault:"5"`
	PasswordResetEmailMax int64         `env:"AUTH_PASSWORD_RESET_EMAIL_MAX" envDefault:"3"`
}

// Config holds all configuration settings for the application.
type Config struct {
	ServerPort  string `env:"API_SERVER_PORT" envDefault:"8080"`
	Environment string `env:"API_ENVIRONMENT" envDefault:"production"`
	Version     string `env:"API_VERSION" envDefault:"v0.1.0"`
	Commit      string `env:"API_COMMIT" envDefault:"unknown"`
	Language    string `env:"API_LANGUAGE" envDefault:"en"`
	Timezone    string `env:"API_TIMEZONE" envDefault:"UTC"`

	StorageDir string `env:"STORAGE_DIR" envDefault:"./storage"`

	TracerDebugKey   string `env:"TRACER_DEBUG_KEY"`
	TracerDebugValue string `env:"TRACER_DEBUG_VALUE"`

	DB        DatabaseConfig
	CORS      CORSConfig
	Logger    LoggerConfig
	Limiter   LimiterConfig
	Banner    BannerConfig
	Security  SecurityConfig
	Redis     RedisConfig
	Storage   StorageConfig
	Telegram  TelegramConfig
	Mail      MailConfig
	Recaptcha RecaptchaConfig
	Auth      AuthConfig
}

// StoragePath returns a path inside StorageDir, e.g. StoragePath("logs", "app.log").
// Anything new the app writes to disk goes through it, so STORAGE_DIR stays the only setting.
func (c *Config) StoragePath(elem ...string) string {
	return filepath.Join(append([]string{c.StorageDir}, elem...)...)
}

// IsDevelopment reports whether the app runs in the development environment.
func (c *Config) IsDevelopment() bool {
	return c.Environment == "development"
}

var (
	mu       sync.Mutex
	instance *Config
	loaded   bool
)

// NewConfig loads configuration from environment variables as a singleton.
func NewConfig() *Config {
	mu.Lock()
	defer mu.Unlock()

	if loaded {
		return instance
	}

	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		panic(fmt.Errorf("load configuration: %w", err))
	}

	if cfg.Storage.BaseURL == "" {
		cfg.Storage.BaseURL = "http://localhost:" + cfg.ServerPort + "/uploads"
	}

	instance = cfg
	loaded = true

	return instance
}

// DSN returns the PostgreSQL connection string for d in the given timezone.
func (d DatabaseConfig) DSN(timezone string) string {
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s timezone=%s",
		d.Host, d.Port, d.User, d.Password, d.Name, d.SSLMode, timezone)
}
