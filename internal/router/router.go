package router

import (
	"compress/gzip"
	"fmt"
	"net/http"
	"path"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/fx"
	"go.uber.org/zap"

	"github.com/jun-develop/junkit/cache"
	"github.com/jun-develop/junkit/middleware"
	"github.com/jun-develop/junkit/notification"
	"github.com/jun-develop/junkit/response"

	"jungo/internal/config"
	policy "jungo/internal/middleware"
)

// Routes defines the interface for registering feature routes.
type Routes interface {
	Register(group *gin.RouterGroup)
}

// Versioned defines an API version prefix for routes.
type Versioned interface {
	Version() string
}

// VersionedRoutes combines Routes and Versioned interfaces.
type VersionedRoutes interface {
	Routes
	Versioned
}

// BodyLimit raises the request body limit (SECURITY_MAX_BODY_SIZE) for one route, e.g. an upload.
// Path is relative to the group Register receives, exactly as passed to group.POST/PUT/...
type BodyLimit struct {
	Method   string
	Path     string
	MaxBytes int64
}

// BodyLimited is implemented by Routes that have routes needing a larger body limit.
type BodyLimited interface {
	BodyLimits() []BodyLimit
}

// Params defines dependencies for route registration.
type Params struct {
	fx.In

	Router        *gin.Engine
	Config        *config.Config
	CacheOptions  cache.Options
	Routes        []Routes              `group:"routes"`
	HTTPLogger    *zap.Logger           `name:"http"`
	LimiterLogger *zap.Logger           `name:"limiter"`
	Notifier      notification.Notifier `optional:"true"`
	Responder     response.Responder
	Guard         *policy.Guard
}

// RegisterAll sets up global middlewares, system routes, and feature routes. It fails when a
// BodyLimit names a route that was never registered, so a typo cannot silently keep the default,
// and when a versioned route is not wrapped by Guard, so a new route cannot ship without a policy.
func RegisterAll(p Params) error {
	// Filled while routes register below; Payload only reads it per request, after startup.
	bodyLimits := make(map[string]int64)
	registerGlobalMiddlewares(p, bodyLimits)
	p.Router.HandleMethodNotAllowed = true

	p.Router.NoRoute(func(ctx *gin.Context) {
		p.Responder.Send(ctx, http.StatusNotFound, "api_not_found")
	})
	p.Router.NoMethod(func(ctx *gin.Context) {
		p.Responder.Send(ctx, http.StatusMethodNotAllowed, "method_not_allowed")
	})
	p.Router.GET("/health", func(ctx *gin.Context) {
		p.Responder.Send(ctx, http.StatusOK, "app_running")
	})
	p.Router.Static("/uploads", p.Config.StoragePath("uploads"))

	api := p.Router.Group("/api")
	versionGroups := make(map[string]*gin.RouterGroup)

	for _, route := range p.Routes {
		target := api

		if v, ok := route.(Versioned); ok && v.Version() != "" {
			version := v.Version()
			group, exists := versionGroups[version]
			if !exists {
				group = api.Group("/" + version)
				versionGroups[version] = group
			}

			target = group
		}

		route.Register(target)

		if bl, ok := route.(BodyLimited); ok {
			for _, l := range bl.BodyLimits() {
				bodyLimits[middleware.RouteKey(l.Method, path.Join(target.BasePath(), l.Path))] = l.MaxBytes
			}
		}
	}

	registered := make(map[string]bool)
	for _, r := range p.Router.Routes() {
		registered[middleware.RouteKey(r.Method, r.Path)] = true

		if inGroup(r.Path, versionGroups) && !p.Guard.Guards(r.HandlerFunc) {
			return fmt.Errorf("router: %s %s is not wrapped by Guard.Can, Guard.Authenticated or Guard.Public", r.Method, r.Path)
		}
	}

	for key := range bodyLimits {
		if !registered[key] {
			return fmt.Errorf("router: body limit for unregistered route %q", key)
		}
	}

	return nil
}

// inGroup reports whether routePath is under one of groups.
func inGroup(routePath string, groups map[string]*gin.RouterGroup) bool {
	for _, g := range groups {
		if strings.HasPrefix(routePath, g.BasePath()+"/") || routePath == g.BasePath() {
			return true
		}
	}

	return false
}

// registerGlobalMiddlewares attaches global middlewares to the router.
func registerGlobalMiddlewares(p Params, bodyLimits map[string]int64) {
	cfg := p.Config
	debug := middleware.TracerDebugOptions{
		QueryKey:     cfg.TracerDebugKey,
		QueryValue:   cfg.TracerDebugValue,
		SecretHeader: "X-Internal-Secret",
		Secret:       cfg.Auth.InternalSecret,
	}

	p.Router.Use(
		middleware.TracerDebug(debug),
		middleware.Security(),
		middleware.Trace(middleware.TraceOptions{
			Version:     cfg.Version,
			Commit:      cfg.Commit,
			Environment: cfg.Environment,
		}),
		middleware.CORS(middleware.CORSOptions{
			AllowOrigins:     cfg.CORS.AllowOrigins,
			AllowMethods:     cfg.CORS.AllowMethods,
			AllowHeaders:     cfg.CORS.AllowHeaders,
			AllowCredentials: cfg.CORS.AllowCredentials,
			MaxAge:           cfg.CORS.MaxAge,
		}),
		middleware.Gzip(middleware.GzipOptions{Level: gzip.BestSpeed}),
		middleware.AccessLog(p.HTTPLogger, middleware.AccessLogOptions{
			SkipIf:            debug.Matches,
			BodiesOnErrorOnly: true,
		}),
		middleware.Recover(p.HTTPLogger, p.Notifier, p.Responder, middleware.RecoverOptions{Debug: debug}),
		middleware.Payload(middleware.PayloadOptions{
			MaxBodySize: cfg.Security.MaxRequestBodySize,
			RouteLimits: bodyLimits,
		}, p.Responder),
	)

	if cfg.Banner.Enabled {
		p.Router.Use(middleware.Banner(middleware.BannerOptions{
			Cache:        cache.New[int64](p.CacheOptions.OrMemory()),
			MaxStrikes:   cfg.Banner.MaxStrikes,
			StrikeWindow: cfg.Banner.StrikeWindow,
			BanDurations: cfg.Banner.BanDurations,
			IPWhitelist:  cfg.Limiter.IPWhitelist,
		}, p.LimiterLogger, p.Responder, p.Notifier))
	}

	p.Router.Use(
		middleware.Limiter(middleware.LimiterOptions{
			RequestsPerSecond: cfg.Limiter.RequestsPerSecond,
			Burst:             cfg.Limiter.Burst,
			NumShards:         cfg.Limiter.NumShards,
			CleanupInterval:   cfg.Limiter.CleanupInterval,
			ClientTTL:         cfg.Limiter.ClientTTL,
			LogTTL:            cfg.Limiter.LogTTL,
			IPWhitelist:       cfg.Limiter.IPWhitelist,
		}, p.LimiterLogger, p.Responder, p.Notifier),
		middleware.RoutePatterns(map[string]func(string) bool{
			"uuid": middleware.IsUUID,
			"id":   middleware.IsID,
			"slug": middleware.IsSlug,
		}, p.Responder),
	)
}
