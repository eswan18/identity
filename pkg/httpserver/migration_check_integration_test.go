//go:build integration

package httpserver

import (
	"context"

	"github.com/eswan18/identity/db/migrations"
)

// TestSchemaVerificationPassesOnMigratedDB confirms the startup schema check
// (migrations.Verify) does NOT false-positive against a correctly-migrated
// database — the suite runs all migrations in setup, so Verify must pass.
func (s *OAuthFlowSuite) TestSchemaVerificationPassesOnMigratedDB() {
	s.Require().NoError(migrations.Verify(context.Background(), s.datastore.DB))
}

// TestSchemaVerificationDetectsPendingMigration confirms the check actually
// fires: it temporarily rewinds schema_migrations to one version behind the
// binary's latest, asserts Verify returns an error, then restores the real
// version. Only this test reads schema_migrations, so the temporary mutation
// is safe for the rest of the suite as long as it's restored here.
func (s *OAuthFlowSuite) TestSchemaVerificationDetectsPendingMigration() {
	ctx := context.Background()

	var orig int
	s.Require().NoError(s.datastore.DB.QueryRowContext(ctx, "SELECT version FROM schema_migrations").Scan(&orig))
	s.Require().Greater(orig, 0)

	_, err := s.datastore.DB.ExecContext(ctx, "UPDATE schema_migrations SET version = $1", orig-1)
	s.Require().NoError(err)
	defer func() {
		_, restoreErr := s.datastore.DB.ExecContext(ctx, "UPDATE schema_migrations SET version = $1", orig)
		s.Require().NoError(restoreErr)
	}()

	s.Require().Error(migrations.Verify(ctx, s.datastore.DB),
		"Verify should reject a database that is behind the binary's migration version")
}
