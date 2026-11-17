package primary

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

// migrationsFS holds the schema the binary was built with, so production migrates without the
// migrate CLI or the source tree.
//
//go:embed migrations/*.sql functions/*.sql
var migrationsFS embed.FS

// migrateLockID is the advisory lock that keeps two migrators (two app instances) from running
// the same migration at once.
const migrateLockID = 7_316_420_195

// createSchemaMigrations creates golang-migrate's version table.
const createSchemaMigrations = `CREATE TABLE IF NOT EXISTS schema_migrations (
    version BIGINT NOT NULL PRIMARY KEY,
    dirty   BOOLEAN NOT NULL
)`

// migration is one numbered up-migration file.
type migration struct {
	version int64
	file    string
}

// Migrate applies the pending up-migrations, then (re)applies every SQL function, and returns the
// files it applied. It keeps golang-migrate's schema_migrations table, so it and `make migrate-up`
// can be used on the same database. Each migration runs in its own transaction; a failed one
// changes nothing.
//
// Usage:
//
//	applied, err := db.Migrate(ctx)
func (d *DB) Migrate(ctx context.Context) ([]string, error) {
	pending, err := upMigrations()
	if err != nil {
		return nil, err
	}

	if err := d.exec(ctx, createSchemaMigrations); err != nil {
		return nil, fmt.Errorf("create schema_migrations: %w", err)
	}

	var applied []string
	for _, m := range pending {
		ran, err := d.applyMigration(ctx, m)
		if err != nil {
			return applied, fmt.Errorf("migration %s: %w", m.file, err)
		}

		if ran {
			applied = append(applied, m.file)
		}
	}

	functions, err := d.applyFunctions(ctx)
	if err != nil {
		return applied, err
	}

	return append(applied, functions...), nil
}

// applyMigration runs m unless the database is already at or past its version, and reports
// whether it ran.
func (d *DB) applyMigration(ctx context.Context, m migration) (bool, error) {
	sql, err := migrationsFS.ReadFile(m.file)
	if err != nil {
		return false, err
	}

	ran := false
	err = d.WithTransaction(ctx, func(ctx context.Context) error {
		if err := d.lockForMigration(ctx); err != nil {
			return err
		}

		current, err := d.schemaVersion(ctx)
		if err != nil || current >= m.version {
			return err
		}

		if err := d.exec(ctx, string(sql)); err != nil {
			return err
		}

		ran = true

		return d.setSchemaVersion(ctx, m.version)
	})

	return ran, err
}

// applyFunctions (re)applies every functions/*.sql (CREATE OR REPLACE, so safe to re-run).
func (d *DB) applyFunctions(ctx context.Context) ([]string, error) {
	files, err := fs.Glob(migrationsFS, "functions/*.sql")
	if err != nil {
		return nil, err
	}

	sort.Strings(files)

	err = d.WithTransaction(ctx, func(ctx context.Context) error {
		if err := d.lockForMigration(ctx); err != nil {
			return err
		}

		for _, file := range files {
			sql, err := migrationsFS.ReadFile(file)
			if err != nil {
				return err
			}

			if err := d.exec(ctx, string(sql)); err != nil {
				return fmt.Errorf("function %s: %w", file, err)
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return files, nil
}

// lockForMigration takes the migration lock until the transaction in ctx ends and lifts
// DB_STATEMENT_TIMEOUT for it: a migration may legitimately run longer than a request.
func (d *DB) lockForMigration(ctx context.Context) error {
	if err := d.exec(ctx, "SELECT pg_advisory_xact_lock($1)", int64(migrateLockID)); err != nil {
		return fmt.Errorf("take migration lock: %w", err)
	}

	return d.exec(ctx, "SET LOCAL statement_timeout = 0")
}

// schemaVersion returns the version in schema_migrations (0 when empty). A dirty version, left by
// a migrate CLI run that failed halfway, must be fixed by hand first.
func (d *DB) schemaVersion(ctx context.Context) (int64, error) {
	var version int64
	var dirty bool

	err := d.Executor(ctx).QueryRow(ctx, "SELECT version, dirty FROM schema_migrations LIMIT 1").Scan(&version, &dirty)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}

	if err != nil {
		return 0, fmt.Errorf("read schema version: %w", err)
	}

	if dirty {
		return 0, fmt.Errorf("database is dirty at version %d: fix it, then run `migrate force %d`", version, version)
	}

	return version, nil
}

// setSchemaVersion records version as the clean current version.
func (d *DB) setSchemaVersion(ctx context.Context, version int64) error {
	if err := d.exec(ctx, "DELETE FROM schema_migrations"); err != nil {
		return err
	}

	return d.exec(ctx, "INSERT INTO schema_migrations (version, dirty) VALUES ($1, false)", version)
}

// exec runs sql on the transaction in ctx or the pool; without args it may hold several statements.
func (d *DB) exec(ctx context.Context, sql string, args ...any) error {
	_, err := d.Executor(ctx).Exec(ctx, sql, args...)
	return err
}

// upMigrations returns the embedded up-migrations ("000001_access.up.sql") in version order.
func upMigrations() ([]migration, error) {
	files, err := fs.Glob(migrationsFS, "migrations/*.up.sql")
	if err != nil {
		return nil, err
	}

	migrations := make([]migration, 0, len(files))
	for _, file := range files {
		prefix, _, ok := strings.Cut(path.Base(file), "_")
		version, err := strconv.ParseInt(prefix, 10, 64)
		if !ok || err != nil {
			return nil, fmt.Errorf("migration %s: name must start with a version number", file)
		}

		migrations = append(migrations, migration{version: version, file: file})
	}

	sort.Slice(migrations, func(i, j int) bool { return migrations[i].version < migrations[j].version })

	return migrations, nil
}
