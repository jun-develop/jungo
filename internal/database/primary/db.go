// Package primary is the app's main PostgreSQL database: its connection, migrations, queries and
// sqlc-generated code.
package primary

import (
	"context"

	"go.uber.org/fx"
	"go.uber.org/zap"

	"github.com/jun-develop/junkit/database"
	"github.com/jun-develop/junkit/database/postgres"
	"github.com/jun-develop/junkit/tracer"

	"jungo/internal/config"
	"jungo/internal/database/primary/sqlc"
)

// DB is the primary PostgreSQL database. It is a distinct type rather than a named *postgres.DB,
// so a repository that declares *primary.DB can only ever be given this database.
type DB struct {
	*postgres.DB
}

// New opens the primary database from cfg.DB.
func New(lc fx.Lifecycle, log *zap.Logger, cfg *config.Config) (*DB, error) {
	opts := options(cfg)
	db, err := postgres.New(opts, log)
	if err != nil {
		return nil, err
	}

	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			if err := db.Ping(ctx); err != nil {
				return err
			}

			log.Info("postgres: connected", zap.String("name", opts.Name), zap.String("dsn", database.MaskDSN(opts.DSN)))

			return nil
		},
		OnStop: func(context.Context) error {
			db.Close()

			return nil
		},
	})

	return &DB{DB: db}, nil
}

// Queries returns the sqlc queries bound to this database, or to its transaction active in ctx.
//
// Usage:
//
//	row, err := r.db.Queries(ctx).GetUserByUUID(ctx, id)
func (d *DB) Queries(ctx context.Context) *sqlc.Queries {
	return sqlc.New(d.Executor(ctx))
}

// options configures the connection pool and query tracing from cfg.DB.
func options(cfg *config.Config) postgres.Options {
	return postgres.Options{
		Name:               "primary",
		DSN:                cfg.DB.DSN(cfg.Timezone),
		MaxConnection:      cfg.DB.MaxConnection,
		MinConnection:      cfg.DB.MinConnection,
		MaxConnLifetime:    cfg.DB.MaxConnLifetime,
		MaxConnIdleTime:    cfg.DB.MaxConnIdleTime,
		HealthCheckPeriod:  cfg.DB.HealthCheckPeriod,
		QueryLogging:       cfg.DB.QueryLogging,
		SlowQueryThreshold: cfg.DB.SlowQueryThreshold,
		Decorate: func(inner postgres.DBTX) postgres.DBTX {
			return tracer.NewPgxWrapper(inner)
		},
	}
}
