//go:build integration

package migrations

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

// TestUpAgainstPostgresAccountDeletion covers migration 000017: existing users
// come out with no deletion pending; the column takes a stamp; then down (the
// column is gone, the user survives) and up again. (Named under
// TestUpAgainstPostgres so CI's integration -run pattern picks it up.)
func TestUpAgainstPostgresAccountDeletion(t *testing.T) {
	ctx := context.Background()

	pg, err := postgres.Run(ctx, "postgres:17",
		postgres.WithDatabase("identity"),
		postgres.WithUsername("postgres"),
		postgres.WithPassword("postgres"),
		postgres.BasicWaitStrategies(),
		postgres.WithSQLDriver("pgx"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pg.Terminate(context.Background()) })
	dbURL, err := pg.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)
	conn, err := sql.Open("pgx", dbURL)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	dir, err := filepath.Abs(".")
	require.NoError(t, err)
	m, err := migrate.New("file://"+dir, dbURL)
	require.NoError(t, err)
	t.Cleanup(func() { m.Close() })

	hasColumn := func(t *testing.T) bool {
		t.Helper()
		var n int
		require.NoError(t, conn.QueryRowContext(ctx, `
			SELECT count(*) FROM information_schema.columns
			WHERE table_name = 'auth_users' AND column_name = 'deletion_requested_at'`).Scan(&n))
		return n == 1
	}

	require.NoError(t, m.Migrate(16))
	_, err = conn.ExecContext(ctx, `INSERT INTO auth_users (username, email, password_hash)
	                               VALUES ('alice', 'alice@example.com', 'x')`)
	require.NoError(t, err)

	require.NoError(t, m.Migrate(17))
	require.True(t, hasColumn(t))
	var pending sql.NullTime
	require.NoError(t, conn.QueryRowContext(ctx,
		`SELECT deletion_requested_at FROM auth_users WHERE username = 'alice'`).Scan(&pending))
	require.False(t, pending.Valid, "existing users have no deletion pending")
	_, err = conn.ExecContext(ctx,
		`UPDATE auth_users SET deletion_requested_at = now() WHERE username = 'alice'`)
	require.NoError(t, err)

	require.NoError(t, m.Migrate(16))
	require.False(t, hasColumn(t))
	var n int
	require.NoError(t, conn.QueryRowContext(ctx, `SELECT count(*) FROM auth_users`).Scan(&n))
	require.Equal(t, 1, n)

	require.NoError(t, m.Migrate(17))
	require.True(t, hasColumn(t))
}
