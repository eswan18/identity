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

// TestUpAgainstPostgresConsentResourceBackfill covers migration 000015: a
// consent given before requests could name a resource is recorded under its
// client's default resource, so nobody is asked again; a client with no
// default keeps NULL. Then down (back to NULL, unless a NULL row already
// exists for that user and client) and up again. (Named under
// TestUpAgainstPostgres so CI's integration -run pattern picks it up.)
func TestUpAgainstPostgresConsentResourceBackfill(t *testing.T) {
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

	exec := func(t *testing.T, query string, args ...any) {
		t.Helper()
		_, err := conn.ExecContext(ctx, query, args...)
		require.NoError(t, err, query)
	}
	// consents returns the resources (NULL as "") of a user's consents for a
	// client, sorted.
	consents := func(t *testing.T, user, client string) []string {
		t.Helper()
		rows, err := conn.QueryContext(ctx, `
			SELECT COALESCE(uc.resource, '')
			FROM oauth_user_consents uc
			JOIN auth_users u ON u.id = uc.user_id
			JOIN oauth_clients c ON c.id = uc.client_id
			WHERE u.username = $1 AND c.client_id = $2
			ORDER BY 1`, user, client)
		require.NoError(t, err)
		defer rows.Close()
		got := []string{}
		for rows.Next() {
			var r string
			require.NoError(t, rows.Scan(&r))
			got = append(got, r)
		}
		require.NoError(t, rows.Err())
		return got
	}
	consent := func(t *testing.T, user, client string, resource any) {
		t.Helper()
		exec(t, `
			INSERT INTO oauth_user_consents (user_id, client_id, resource, scopes)
			SELECT u.id, c.id, $3, '{openid}'
			FROM auth_users u, oauth_clients c
			WHERE u.username = $1 AND c.client_id = $2`, user, client, resource)
	}

	require.NoError(t, m.Migrate(14))
	exec(t, `INSERT INTO oauth_resources (uri, name) VALUES ('ethanswan:fitness', 'Fitness'), ('https://other.example', 'Other')`)
	for _, c := range []struct{ id, def any }{{"footstrike", "ethanswan:fitness"}, {"login-only", nil}, {"both", "ethanswan:fitness"}} {
		exec(t, `INSERT INTO oauth_clients (client_id, name, redirect_uris, allowed_scopes, is_confidential, default_resource)
		         VALUES ($1, $1, '{https://app.example/cb}', '{openid}', false, $2)`, c.id, c.def)
	}
	for _, u := range []string{"alice", "bob"} {
		exec(t, `INSERT INTO auth_users (username, password_hash, email) VALUES ($1, 'x', $1 || '@example.com')`, u)
	}
	consent(t, "alice", "footstrike", nil) // given before resources existed
	consent(t, "alice", "login-only", nil) // a client with no default
	consent(t, "bob", "footstrike", nil)
	consent(t, "bob", "footstrike", "https://other.example") // a per-resource consent

	require.NoError(t, m.Migrate(15))
	require.Equal(t, []string{"ethanswan:fitness"}, consents(t, "alice", "footstrike"), "recorded under the client's default")
	require.Equal(t, []string{""}, consents(t, "alice", "login-only"), "no default: still no resource")
	require.Equal(t, []string{"ethanswan:fitness", "https://other.example"}, consents(t, "bob", "footstrike"))

	// The previous release, still serving in the rollout, writes a NULL
	// consent for a user the new release has under the default.
	consent(t, "alice", "footstrike", nil)

	require.NoError(t, m.Migrate(14))
	require.Equal(t, []string{"", "ethanswan:fitness"}, consents(t, "alice", "footstrike"),
		"a NULL row already exists, so the default one stays rather than collide")
	require.Equal(t, []string{"", "https://other.example"}, consents(t, "bob", "footstrike"),
		"back to NULL; another resource's consent is 000014's down to deal with")
	require.Equal(t, []string{""}, consents(t, "alice", "login-only"))

	require.NoError(t, m.Migrate(15))
	require.Equal(t, []string{"ethanswan:fitness", "https://other.example"}, consents(t, "bob", "footstrike"))
	require.Equal(t, []string{"", "ethanswan:fitness"}, consents(t, "alice", "footstrike"),
		"up again leaves a NULL row alone where the default one already exists")
}
