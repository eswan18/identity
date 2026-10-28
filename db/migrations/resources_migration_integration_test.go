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

// TestUpAgainstPostgresResourcesMigration covers migration 000012 (the
// resources registry, expand step) against data shaped like production's:
// the backfill, that the previous release keeps working against the expanded
// schema, and up/down/up. (Named under TestUpAgainstPostgres so CI's
// integration -run pattern picks it up.)
//
// It steps to explicit versions rather than "latest", so later migrations
// don't change what it checks.
func TestUpAgainstPostgresResourcesMigration(t *testing.T) {
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
	queryString := func(t *testing.T, query string, args ...any) sql.NullString {
		t.Helper()
		var v sql.NullString
		require.NoError(t, conn.QueryRowContext(ctx, query, args...).Scan(&v), query)
		return v
	}
	count := func(t *testing.T, query string, args ...any) int {
		t.Helper()
		var n int
		require.NoError(t, conn.QueryRowContext(ctx, query, args...).Scan(&n), query)
		return n
	}
	clientUUID := func(t *testing.T, clientID string) string {
		t.Helper()
		return queryString(t, `SELECT id::text FROM oauth_clients WHERE client_id = $1`, clientID).String
	}

	// Version 11, with clients the way the old schema held them.
	require.NoError(t, m.Migrate(11))
	insertClient := func(t *testing.T, clientID, name, audience string) {
		exec(t, `INSERT INTO oauth_clients (client_id, name, redirect_uris, allowed_scopes, is_confidential, audience)
		      VALUES ($1, $2, '{https://app.example/cb}', '{openid}', false, $3)`, clientID, name, audience)
	}
	insertClient(t, "footstrike", "Footstrike Dashboard", "ethanswan:fitness")
	insertClient(t, "shared-a", "Shared A", "https://Shared.Example/api/") // not canonical: must survive as-is
	insertClient(t, "shared-b", "Shared B", "https://Shared.Example/api/")
	insertClient(t, "no-audience", "No Audience", "")

	exec(t, `INSERT INTO auth_users (username, password_hash, email) VALUES ('u', 'x', 'u@example.com')`)
	userID := queryString(t, `SELECT id::text FROM auth_users WHERE username = 'u'`).String
	insertToken := func(t *testing.T, refresh, clientID string) {
		exec(t, `INSERT INTO oauth_tokens (access_token, refresh_token, user_id, client_id, scope, expires_at)
		      VALUES ($1, $1, $2, $3, '{openid}', now() + interval '1 hour')`, refresh, userID, clientUUID(t, clientID))
	}
	insertToken(t, "tok-footstrike", "footstrike")
	insertToken(t, "tok-no-audience", "no-audience")
	exec(t, `INSERT INTO oauth_user_consents (user_id, client_id, scopes) VALUES ($1, $2, '{openid}')`,
		userID, clientUUID(t, "footstrike"))

	t.Run("up backfills resources byte for byte", func(t *testing.T) {
		require.NoError(t, m.Migrate(12))

		require.Equal(t, 2, count(t, `SELECT count(*) FROM oauth_resources`))
		require.Equal(t, "Footstrike Dashboard",
			queryString(t, `SELECT name FROM oauth_resources WHERE uri = 'ethanswan:fitness'`).String,
			"a resource one client uses is named after that client")
		require.Equal(t, "https://Shared.Example/api/",
			queryString(t, `SELECT name FROM oauth_resources WHERE uri = 'https://Shared.Example/api/'`).String,
			"a resource several clients share is named by its URI")
		require.Equal(t, 0, count(t, `SELECT count(*) FROM oauth_resources WHERE dynamic_clients OR scopes <> '{}'::jsonb`))

		for clientID, want := range map[string]sql.NullString{
			"footstrike":  {String: "ethanswan:fitness", Valid: true},
			"shared-a":    {String: "https://Shared.Example/api/", Valid: true},
			"shared-b":    {String: "https://Shared.Example/api/", Valid: true},
			"no-audience": {},
		} {
			require.Equal(t, want, queryString(t, `SELECT default_resource FROM oauth_clients WHERE client_id = $1`, clientID), clientID)
		}
		require.Equal(t, 4, count(t, `SELECT count(*) FROM oauth_clients WHERE kind = 'registered' AND metadata_fetched_at IS NULL`))

		require.Equal(t, sql.NullString{String: "ethanswan:fitness", Valid: true},
			queryString(t, `SELECT resource FROM oauth_tokens WHERE refresh_token = 'tok-footstrike'`))
		require.False(t, queryString(t, `SELECT resource FROM oauth_tokens WHERE refresh_token = 'tok-no-audience'`).Valid)
		require.False(t, queryString(t, `SELECT resource FROM oauth_user_consents`).Valid)
	})

	t.Run("the previous release keeps working", func(t *testing.T) {
		// Its token INSERT names no resource; the trigger records the aud it minted.
		insertToken(t, "tok-old-release", "shared-a")
		require.Equal(t, sql.NullString{String: "https://Shared.Example/api/", Valid: true},
			queryString(t, `SELECT resource FROM oauth_tokens WHERE refresh_token = 'tok-old-release'`))

		// Its consent upsert names the old (user, client) key.
		exec(t, `INSERT INTO oauth_user_consents (user_id, client_id, scopes) VALUES ($1, $2, '{openid,profile}')
		      ON CONFLICT (user_id, client_id) DO UPDATE SET scopes = EXCLUDED.scopes`, userID, clientUUID(t, "footstrike"))
		require.Equal(t, 1, count(t, `SELECT count(*) FROM oauth_user_consents`))

		// It still creates clients with an audience.
		insertClient(t, "old-release-client", "Old Release", "ethanswan:fitness")
	})

	t.Run("this release's writes", func(t *testing.T) {
		// A client with no audience at all is now allowed.
		exec(t, `INSERT INTO oauth_clients (client_id, name, redirect_uris, is_confidential, default_resource)
		      VALUES ('new-client', 'New', '{https://app.example/cb}', false, 'ethanswan:fitness')`)
		// A default must name a registered resource.
		_, err := conn.ExecContext(ctx, `UPDATE oauth_clients SET default_resource = 'https://unknown.example' WHERE client_id = 'new-client'`)
		require.Error(t, err, "default_resource is a foreign key to oauth_resources(uri)")
		// kind is constrained.
		_, err = conn.ExecContext(ctx, `UPDATE oauth_clients SET kind = 'other' WHERE client_id = 'new-client'`)
		require.Error(t, err)

		// The new consent key treats NULL as a value: one no-resource row per (user, client).
		_, err = conn.ExecContext(ctx, `INSERT INTO oauth_user_consents (user_id, client_id, scopes, resource)
		      VALUES ($1, $2, '{openid}', NULL)`, userID, clientUUID(t, "footstrike"))
		require.Error(t, err, "a second no-resource consent for the same user and client must conflict")
		exec(t, `INSERT INTO oauth_user_consents (user_id, client_id, scopes) VALUES ($1, $2, '{openid}')
		      ON CONFLICT (user_id, client_id, resource) DO UPDATE SET scopes = EXCLUDED.scopes`, userID, clientUUID(t, "footstrike"))
		require.Equal(t, 1, count(t, `SELECT count(*) FROM oauth_user_consents`))

		// This release always names the resource -- the issuer, for a token for
		// identity itself -- and the trigger never overrides a value it was given,
		// even for a client whose default is some other resource.
		exec(t, `INSERT INTO oauth_tokens (access_token, refresh_token, user_id, client_id, scope, expires_at, resource)
		      VALUES ('tok-identity', 'tok-identity', $1, $2, '{openid}', now() + interval '1 hour', 'https://identity.example')`,
			userID, clientUUID(t, "shared-a"))
		require.Equal(t, sql.NullString{String: "https://identity.example", Valid: true},
			queryString(t, `SELECT resource FROM oauth_tokens WHERE refresh_token = 'tok-identity'`))
	})

	t.Run("down restores the old schema", func(t *testing.T) {
		require.NoError(t, m.Migrate(11))

		require.Equal(t, 0, count(t, `SELECT count(*) FROM information_schema.tables WHERE table_name IN ('oauth_resources', 'oauth_client_resources')`))
		require.Equal(t, 0, count(t, `SELECT count(*) FROM information_schema.columns
		      WHERE (table_name = 'oauth_clients' AND column_name IN ('default_resource', 'kind', 'metadata_fetched_at'))
		         OR (table_name = 'oauth_tokens' AND column_name IN ('resource', 'family_id', 'revoked_reason'))
		         OR (table_name IN ('oauth_authorization_codes', 'oauth_user_consents') AND column_name = 'resource')`))
		require.Equal(t, "NO", queryString(t, `SELECT is_nullable FROM information_schema.columns
		      WHERE table_name = 'oauth_clients' AND column_name = 'audience'`).String)

		for clientID, want := range map[string]string{
			"footstrike":  "ethanswan:fitness",
			"shared-a":    "https://Shared.Example/api/",
			"no-audience": "",
			"new-client":  "ethanswan:fitness", // created with no audience, by default_resource
		} {
			require.Equal(t, want, queryString(t, `SELECT audience FROM oauth_clients WHERE client_id = $1`, clientID).String, clientID)
		}
	})

	t.Run("up again", func(t *testing.T) {
		require.NoError(t, m.Migrate(12))
		require.Equal(t, 2, count(t, `SELECT count(*) FROM oauth_resources`))
		require.Equal(t, sql.NullString{String: "ethanswan:fitness", Valid: true},
			queryString(t, `SELECT default_resource FROM oauth_clients WHERE client_id = 'new-client'`))
		require.Equal(t, "ethanswan:fitness",
			queryString(t, `SELECT name FROM oauth_resources WHERE uri = 'ethanswan:fitness'`).String,
			"several clients now share it, so it is named by its URI")
	})
}
