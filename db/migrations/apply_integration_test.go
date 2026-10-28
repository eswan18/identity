//go:build integration

package migrations

import (
	"context"
	"database/sql"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

// TestUpAgainstPostgres exercises the `auth-service migrate` runner against a
// real Postgres, standing in for a preview environment's freshly-branched
// database. The subtests share one container and run in order: the first
// migrates an unmigrated database, the second re-runs against the now
// up-to-date database the way the initContainer does on every pod restart.
func TestUpAgainstPostgres(t *testing.T) {
	ctx := context.Background()

	pgContainer, err := postgres.Run(
		ctx,
		"postgres:17",
		postgres.WithDatabase("identity"),
		postgres.WithUsername("postgres"),
		postgres.WithPassword("postgres"),
		postgres.BasicWaitStrategies(),
		postgres.WithSQLDriver("pgx"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pgContainer.Terminate(context.Background()) })

	databaseURL, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	conn, err := sql.Open("pgx", databaseURL)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	latest, err := LatestVersion()
	require.NoError(t, err)

	// Precondition: an unmigrated database is exactly what the startup check
	// refuses to serve against, which is why the subcommand has to exist.
	require.Error(t, Verify(ctx, conn), "startup check should reject an unmigrated database")

	t.Run("applies pending migrations", func(t *testing.T) {
		require.NoError(t, Up(databaseURL))

		var version int
		var dirty bool
		require.NoError(t, conn.QueryRowContext(ctx, "SELECT version, dirty FROM schema_migrations").Scan(&version, &dirty))
		require.Equal(t, latest, version, "database should be at the version this build embeds")
		require.False(t, dirty)

		// The real postcondition: the schema the service refused to start
		// against a moment ago now passes the same check.
		require.NoError(t, Verify(ctx, conn), "startup check should pass after migrating")
	})

	t.Run("already at latest is a success", func(t *testing.T) {
		require.NoError(t, Up(databaseURL),
			"re-running against an up-to-date database must succeed: golang-migrate reports ErrNoChange, "+
				"and the preview initContainer runs on every pod start")
		require.NoError(t, Verify(ctx, conn))
	})

	// 000013 adds auth_mfa_pending.authorize_query, the carried authorization
	// request. Its down must remove exactly that and leave a schema the up
	// applies to again. Down migrations are not embedded (see apply.go), so
	// this reads them from disk. It migrates down to 11 rather than one step,
	// so it keeps exercising 000013's down after later migrations land.
	t.Run("000013 down and up again", func(t *testing.T) {
		m, err := migrate.New("file://.", databaseURL)
		require.NoError(t, err)
		t.Cleanup(func() { _, _ = m.Close() })

		hasColumn := func() bool {
			var n int
			require.NoError(t, conn.QueryRowContext(ctx,
				`SELECT count(*) FROM information_schema.columns
				 WHERE table_name = 'auth_mfa_pending' AND column_name = 'authorize_query'`).Scan(&n))
			return n == 1
		}
		require.True(t, hasColumn(), "000013 should add auth_mfa_pending.authorize_query")

		require.NoError(t, m.Migrate(11))
		require.False(t, hasColumn(), "000013's down should drop authorize_query")

		require.NoError(t, m.Up())
		require.True(t, hasColumn())
		require.NoError(t, Verify(ctx, conn))
	})
}
