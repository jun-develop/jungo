package router

import (
	"compress/gzip"
	"fmt"
	"net/http"
	"path"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/fx"
	"go.uber.org/zap"

	"github.com/jun-develop/junkit/apidoc"
	"github.com/jun-develop/junkit/cache"
	"github.com/jun-develop/junkit/middleware"
	"github.com/jun-develop/junkit/notification"
	"github.com/jun-develop/junkit/response"

	"jungo/internal/common/actor"
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

// Documented is implemented by every Routes: it describes each of its routes for the API docs.
// Like BodyLimit, a Route's Path is relative to the group Register receives.
type Documented interface {
	Docs() []apidoc.Route
}

// apiPrefix is where every feature route lives.
const apiPrefix = "/api"

// Params defines dependencies for route registration.
type Params struct {
	fx.In

	Router        *gin.Engine
	Config        *config.Config
	Cache         *cache.Store
	Routes        []Routes              `group:"routes"`
	HTTPLogger    *zap.Logger           `name:"http"`
	LimiterLogger *zap.Logger           `name:"limiter"`
	Notifier      notification.Notifier `optional:"true"`
	Responder     response.Responder
	Guard         *policy.Guard
	AuthErrors    policy.AuthErrors
	// Permissions are every permission code the features declare, the PermissionCode enum of the docs.
	Permissions []string `group:"permissions"`
}

// RegisterAll sets up global middlewares, system routes, and feature routes. It fails when a
// BodyLimit or doc names a route that was never registered, so a typo cannot go unnoticed, and when
// a route under /api is not wrapped by Guard or not documented, so a new route cannot ship without
// a policy or docs. In development it serves the API docs at /docs.
func RegisterAll(p Params) error {
	registerUploads(p)

	// Filled while routes register below; Payload only reads it per request, after startup.
	bodyLimits := make(map[string]int64)
	docs := make(map[string]apidoc.Route)
	registerGlobalMiddlewares(p, bodyLimits)
	registerSystemRoutes(p)
	registerFeatureRoutes(p, bodyLimits, docs)

	ops, err := verifyRoutes(p, bodyLimits, docs)
	if err != nil {
		return err
	}

	if !p.Config.IsDevelopment() {
		return nil
	}

	info := apidoc.Info{Title: "Jungo API", Version: p.Config.Version, Enums: []apidoc.Enum{
		apidoc.EnumOf[actor.PermissionCode](slices.Sorted(slices.Values(p.Permissions))...),
	}}

	spec, err := apidoc.Spec(info, ops)
	if err != nil {
		return fmt.Errorf("router: api docs: %w", err)
	}
	apidoc.Register(p.Router, "/docs", "API docs", spec)

	return nil
}

// registerUploads serves uploaded files. Registered before the global middlewares, they skip gzip
// (images are already compressed), the access log and body parsing, but keep the security headers
// (nosniff matters for user files) and panic recovery.
func registerUploads(p Params) {
	uploads := p.Router.Group("/uploads",
		// Cross-origin: uploaded images are embedded by the frontend, which may be on another site.
		middleware.Security(middleware.SecurityOptions{
			ForceHSTS:                 p.Config.Security.ForceHSTS,
			CrossOriginResourcePolicy: "cross-origin",
		}),
		middleware.Recover(middleware.RecoverOptions{}, p.HTTPLogger, p.Notifier, p.Responder),
	)
	uploads.Static("/", p.Config.StoragePath("uploads"))
}

// registerSystemRoutes registers the health check and the 404/405 answers.
func registerSystemRoutes(p Params) {
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
}

// registerFeatureRoutes registers every feature's routes under /api, or /api/<version>, and
// records their body limits and docs.
func registerFeatureRoutes(p Params, bodyLimits map[string]int64, docs map[string]apidoc.Route) {
	api := p.Router.Group(apiPrefix)
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

		if d, ok := route.(Documented); ok {
			for _, doc := range d.Docs() {
				doc.Path = path.Join(target.BasePath(), doc.Path)
				docs[middleware.RouteKey(doc.Method, doc.Path)] = doc
			}
		}
	}
}

// verifyRoutes checks every /api route is wrapped by Guard and documented, and every body limit and
// doc names a route. It returns the documented operations of the public API, each with the errors the
// middlewares in front of it can answer; internal routes are left out, as no client of the docs calls
// them.
func verifyRoutes(p Params, bodyLimits map[string]int64, docs map[string]apidoc.Route) ([]apidoc.Operation, error) {
	registered := make(map[string]bool)
	var ops []apidoc.Operation

	for _, r := range p.Router.Routes() {
		key := middleware.RouteKey(r.Method, r.Path)
		registered[key] = true

		if !strings.HasPrefix(r.Path, apiPrefix+"/") {
			continue
		}

		pol, ok := p.Guard.Policy(r.HandlerFunc)
		if !ok {
			return nil, fmt.Errorf("router: %s %s is not wrapped by Guard.Can, Guard.Authenticated, Guard.Public or Guard.Internal", r.Method, r.Path)
		}

		doc, ok := docs[key]
		if !ok {
			return nil, fmt.Errorf("router: %s %s has no apidoc.Route in its Routes' Docs()", r.Method, r.Path)
		}

		if pol.Kind == policy.PolicyInternal {
			continue
		}

		doc.Errors = append(middlewareErrors(p, r.Path, doc, pol), doc.Errors...)
		ops = append(ops, apidoc.Operation{Route: doc, Tag: docTag(r.Path), Security: docSecurity(pol)})
	}

	for key := range bodyLimits {
		if !registered[key] {
			return nil, fmt.Errorf("router: body limit for unregistered route %q", key)
		}
	}

	for key := range docs {
		if !registered[key] {
			return nil, fmt.Errorf("router: apidoc.Route for unregistered route %q", key)
		}
	}

	return ops, nil
}

// middlewareErrors returns the errors the global middlewares, the path patterns and the route's Guard
// policy can answer before or around its handler.
func middlewareErrors(p Params, routePath string, doc apidoc.Route, pol policy.Policy) []*response.AppError {
	// Banner is listed even when off here: the docs are built in development, the API runs elsewhere.
	errs := []*response.AppError{middleware.ErrTooManyRequests, middleware.ErrAccessDenied, response.ErrInternalServer}

	if doc.Body != nil {
		errs = append(errs, middleware.ErrBodyTooLarge, middleware.ErrInvalidBody)
	}

	for _, seg := range strings.Split(routePath, "/") {
		if name, ok := strings.CutPrefix(seg, ":"); ok && routePatterns[name] != nil {
			errs = append(errs, middleware.ErrAPINotFound)
			break
		}
	}

	switch pol.Kind {
	case policy.PolicyPermission:
		errs = append(append(errs, p.AuthErrors...), actor.ErrForbidden)
	case policy.PolicyAuthenticated:
		errs = append(errs, p.AuthErrors...)
	}

	return errs
}

// routePatterns are the rules path parameters must match; a mismatch is answered with 404.
var routePatterns = map[string]func(string) bool{
	"uuid": middleware.IsUUID,
	"id":   middleware.IsID,
	"slug": middleware.IsSlug,
}

// docTag groups a route in the docs by the first path segment after /api and its version.
func docTag(routePath string) string {
	segments := strings.Split(strings.TrimPrefix(routePath, apiPrefix+"/"), "/")
	if len(segments) > 1 && len(segments[0]) > 1 && segments[0][0] == 'v' && strings.Trim(segments[0][1:], "0123456789") == "" {
		segments = segments[1:]
	}

	return segments[0]
}

// docSecurity describes a Guard policy for the docs.
func docSecurity(p policy.Policy) apidoc.Security {
	switch p.Kind {
	case policy.PolicyPermission:
		return apidoc.Security{Bearer: true, Permissions: p.Permissions}
	case policy.PolicyAuthenticated:
		return apidoc.Security{Bearer: true}
	case policy.PolicyInternal:
		return apidoc.Security{APIKeyHeader: policy.InternalSecretHeader}
	default:
		return apidoc.Security{}
	}
}

// registerGlobalMiddlewares attaches global middlewares to the router. Banner and Limiter run before
// Payload, so a banned or rate-limited client never makes the server read its body.
func registerGlobalMiddlewares(p Params, bodyLimits map[string]int64) {
	cfg := p.Config
	debug := middleware.TracerDebugOptions{
		QueryKey:     cfg.TracerDebugKey,
		QueryValue:   cfg.TracerDebugValue,
		SecretHeader: policy.InternalSecretHeader,
		Secret:       cfg.Auth.InternalSecret,
	}

	p.Router.Use(
		middleware.TracerDebug(debug),
		middleware.Security(middleware.SecurityOptions{ForceHSTS: cfg.Security.ForceHSTS}),
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
		middleware.AccessLog(middleware.AccessLogOptions{
			SkipIf:            debug.Matches,
			BodiesOnErrorOnly: true,
		}, p.HTTPLogger),
		middleware.Recover(middleware.RecoverOptions{Debug: debug}, p.HTTPLogger, p.Notifier, p.Responder),
	)

	if cfg.Banner.Enabled {
		p.Router.Use(middleware.Banner(middleware.BannerOptions{
			Cache:        cache.New[int64](p.Cache.OrMemory()),
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
		middleware.Payload(middleware.PayloadOptions{
			MaxBodySize: cfg.Security.MaxRequestBodySize,
			RouteLimits: bodyLimits,
		}, p.Responder),
		middleware.RoutePatterns(routePatterns, p.Responder),
	)
}
