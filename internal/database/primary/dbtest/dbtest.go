// Package dbtest gives repository integration tests the database at TEST_DATABASE_URL; tests that
// use it skip when the variable is unset, so `go test ./...` still runs without a database.
package dbtest

import (
	"context"
	"errors"
	"os"
	"runtime"
	"testing"

	"go.uber.org/zap"

	"github.com/jun-develop/junkit/database/postgres"

	"jungo/internal/database/primary"
)

// errRollback ends a test transaction so nothing it wrote is kept.
var errRollback = errors.New("rollback")

// errStopped is panicked when a test stops (t.Fatal) inside InRollback's transaction:
// WithTransaction would otherwise commit, since fn never returned an error.
var errStopped = errors.New("dbtest: test stopped inside the transaction")

// Open opens and migrates the database at TEST_DATABASE_URL, skipping the test when it is unset.
func Open(t *testing.T) *primary.DB {
	t.Helper()

	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}

	pg, err := postgres.New(postgres.Options{Name: "test", DSN: dsn}, zap.NewNop())
	if err != nil {
		t.Fatalf("open database: %v", err)
	}

	t.Cleanup(pg.Close)

	db := &primary.DB{DB: pg}
	if _, err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	return db
}

// InRollback runs fn in a transaction that is always rolled back, so a test leaves nothing behind,
// even when fn stops it with t.Fatal. Inside it now() is the transaction's start, the same for every row.
func InRollback(t *testing.T, db *primary.DB, fn func(ctx context.Context)) {
	t.Helper()

	defer func() {
		if p := recover(); p != nil {
			if p == errStopped {
				// Rolled back; finish stopping the test.
				runtime.Goexit()
			}

			panic(p)
		}
	}()

	err := db.WithTransaction(context.Background(), func(ctx context.Context) error {
		returned := false
		defer func() {
			if !returned {
				// WithTransaction rolls back on a panic.
				panic(errStopped)
			}
		}()

		fn(ctx)
		returned = true

		return errRollback
	})
	if !errors.Is(err, errRollback) {
		t.Fatalf("transaction error = %v", err)
	}
}
