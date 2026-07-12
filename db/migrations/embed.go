// Package migrations embeds the SQL migration files into the binary and
// provides a fail-closed startup check (Verify) that the database schema
// matches the migrations this binary was built with.
//
// It deliberately does NOT apply migrations. The goal is to refuse to start —
// with a clear, actionable error — when code is deployed without running
// `make migrate-up`, rather than silently serving against a schema the code
// doesn't expect (which is how a forgotten migration once broke client-secret
// auth). Applying migrations remains a deliberate, separate step.
package migrations

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
)

// upFiles embeds the "up" migrations so the binary carries the schema version
// it was built for. Only *.up.sql is needed to determine the latest version.
//
//go:embed *.up.sql
var upFiles embed.FS

// LatestVersion returns the highest migration version embedded in the binary,
// i.e. the numeric prefix of the newest *.up.sql file (e.g. 11 for
// 000011_add_mfa_enrollment_pending.up.sql).
func LatestVersion() (int, error) {
	entries, err := fs.ReadDir(upFiles, ".")
	if err != nil {
		return 0, fmt.Errorf("reading embedded migrations: %w", err)
	}
	latest := -1
	for _, e := range entries {
		name := e.Name()
		i := strings.IndexByte(name, '_')
		if i <= 0 {
			continue
		}
		n, err := strconv.Atoi(name[:i])
		if err != nil {
			continue
		}
		if n > latest {
			latest = n
		}
	}
	if latest < 0 {
		return 0, errors.New("no embedded migration files found")
	}
	return latest, nil
}

// Verify checks that the database schema is at exactly the migration version
// this binary was built with, returning a descriptive error otherwise. It
// reads golang-migrate's schema_migrations table (version, dirty) and compares
// it against LatestVersion. It never applies migrations.
//
// Any mismatch — an unreadable/empty schema_migrations table (never migrated),
// a dirty state (a migration failed partway), or a version that differs from
// what the binary expects — is returned as an error so the caller can refuse
// to start.
func Verify(ctx context.Context, db *sql.DB) error {
	latest, err := LatestVersion()
	if err != nil {
		return err
	}

	var version int
	var dirty bool
	err = db.QueryRowContext(ctx, "SELECT version, dirty FROM schema_migrations").Scan(&version, &dirty)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("schema_migrations is empty: no migrations have been applied; run `make migrate-up` (this build expects version %d)", latest)
	case err != nil:
		return fmt.Errorf("could not read schema_migrations (migrations may never have been run): %w; run `make migrate-up`", err)
	case dirty:
		return fmt.Errorf("database schema is dirty at migration %d: a previous migration failed partway and must be resolved manually", version)
	case version != latest:
		return fmt.Errorf("database schema is at migration %d but this build expects %d; run `make migrate-up`", version, latest)
	}
	return nil
}
