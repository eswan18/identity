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

// TestUpAgainstPostgresTrustedClients covers migration 000016: every existing
// client comes out untrusted; a registered client can be trusted; a
// metadata-document (cimd) client never can, whether inserted trusted or
// updated to it, and a trusted client cannot become a cimd one; then down
// (the column and constraint are gone) and up again. (Named under
// TestUpAgainstPostgres so CI's integration -run pattern picks it up.)
func TestUpAgainstPostgresTrustedClients(t *testing.T) {
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

	exec := func(t *testing.T, query string, args ...any) error {
		t.Helper()
		_, err := conn.ExecContext(ctx, query, args...)
		return err
	}
	mustExec := func(t *testing.T, query string, args ...any) {
		t.Helper()
		require.NoError(t, exec(t, query, args...), query)
	}
	trusted := func(t *testing.T, clientID string) bool {
		t.Helper()
		var v bool
		require.NoError(t, conn.QueryRowContext(ctx,
			`SELECT trusted FROM oauth_clients WHERE client_id = $1`, clientID).Scan(&v))
		return v
	}
	hasColumn := func(t *testing.T) bool {
		t.Helper()
		var n int
		require.NoError(t, conn.QueryRowContext(ctx, `
			SELECT count(*) FROM information_schema.columns
			WHERE table_name = 'oauth_clients' AND column_name = 'trusted'`).Scan(&n))
		return n == 1
	}
	const cimdURL = "https://claude.ai/oauth/claude-code-client-metadata"

	require.NoError(t, m.Migrate(15))
	mustExec(t, `INSERT INTO oauth_clients (client_id, name, redirect_uris, allowed_scopes, is_confidential)
	             VALUES ('first-party', 'First Party', '{https://app.example/cb}', '{openid}', false)`)
	mustExec(t, `INSERT INTO oauth_clients (client_id, name, redirect_uris, allowed_scopes, is_confidential, kind)
	             VALUES ($1, 'Claude', '{https://claude.ai/api/mcp/auth_callback}', '{}', false, 'cimd')`, cimdURL)

	require.NoError(t, m.Migrate(16))
	require.False(t, trusted(t, "first-party"), "existing clients come out untrusted")
	require.False(t, trusted(t, cimdURL))

	mustExec(t, `UPDATE oauth_clients SET trusted = true WHERE client_id = 'first-party'`)
	require.True(t, trusted(t, "first-party"), "a registered client can be trusted")

	require.Error(t, exec(t, `UPDATE oauth_clients SET trusted = true WHERE client_id = $1`, cimdURL),
		"a metadata-document client can never be trusted")
	require.False(t, trusted(t, cimdURL))
	require.Error(t, exec(t, `INSERT INTO oauth_clients (client_id, name, redirect_uris, allowed_scopes, is_confidential, kind, trusted)
	                          VALUES ('https://other.example/client.json', 'X', '{https://other.example/cb}', '{}', false, 'cimd', true)`),
		"nor inserted trusted")
	require.Error(t, exec(t, `UPDATE oauth_clients SET kind = 'cimd' WHERE client_id = 'first-party'`),
		"nor can a trusted client become a metadata-document one")

	require.NoError(t, m.Migrate(15))
	require.False(t, hasColumn(t), "down drops the column")
	mustExec(t, `INSERT INTO oauth_clients (client_id, name, redirect_uris, allowed_scopes, is_confidential, kind)
	             VALUES ('https://after-down.example/client.json', 'X', '{https://after-down.example/cb}', '{}', false, 'cimd')`)

	require.NoError(t, m.Migrate(16))
	require.True(t, hasColumn(t))
	require.False(t, trusted(t, "first-party"), "up again starts everyone untrusted")
	require.Error(t, exec(t, `UPDATE oauth_clients SET trusted = true WHERE kind = 'cimd'`))
}
