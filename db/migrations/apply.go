package migrations

import (
	"errors"
	"fmt"
	"log"

	"github.com/golang-migrate/migrate/v4"
	// Registers the "postgres"/"postgresql" schemes with golang-migrate so
	// NewWithSourceInstance can open a DATABASE_URL of either form.
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

// Up applies every pending up migration to the database at databaseURL.
//
// Nothing calls this implicitly. It runs only when someone explicitly asks for
// it via `auth-service migrate` (see cmd/auth-service/main.go) — a human, or
// the migrate initContainer of a preview environment that needs this branch's
// migrations applied to its own database branch. Startup is unchanged: it still
// calls Verify, still applies nothing, and still refuses to serve against a
// schema this build doesn't expect. The prod and staging Deployments run the
// binary bare and never reach this function, so a forgotten `make migrate-up`
// still fails closed there exactly as it did before. See the package comment.
//
// Migrations are read out of the embedded FS through golang-migrate's iofs
// source, so the binary carries its own migrations and needs no files on disk.
// Embedding only *.up.sql is sufficient: iofs indexes a version as soon as it
// sees a file for either direction, and the up path only ever calls ReadUp.
//
// A database already at the latest version is a success, not a failure.
// golang-migrate reports that case as ErrNoChange, and the preview
// initContainer runs on *every* pod start — treating "nothing to do" as an
// error would break every restart of an already-migrated preview.
func Up(databaseURL string) error {
	src, err := iofs.New(upFiles, ".")
	if err != nil {
		return fmt.Errorf("reading embedded migrations: %w", err)
	}

	m, err := migrate.NewWithSourceInstance("iofs", src, databaseURL)
	if err != nil {
		return fmt.Errorf("opening database for migration: %w", err)
	}
	defer func() {
		// Teardown problems are logged, not returned: by this point the
		// migration has already succeeded or failed on its own terms, and
		// failing the process over a connection close would fail the preview
		// initContainer for nothing.
		if srcErr, dbErr := m.Close(); srcErr != nil || dbErr != nil {
			log.Printf("warning: closing migration source/database (source=%v, database=%v)", srcErr, dbErr)
		}
	}()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("applying migrations: %w", err)
	}
	return nil
}
