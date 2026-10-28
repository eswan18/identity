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

// TestUpAgainstPostgresContractMigration covers migration 000014, the contract
// step for 000012 and 000013, against data written the way the rollout wrote
// it: rows from before 000012, and rows the previous release inserted while it
// was still serving against the expanded schema. Then down to 13, further down
// through 000012's down, and up again. (Named under TestUpAgainstPostgres so
// CI's integration -run pattern picks it up.)
//
// It steps to explicit versions rather than "latest", so later migrations
// don't change what it checks.
func TestUpAgainstPostgresContractMigration(t *testing.T) {
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
	columns := func(t *testing.T, table string, names ...string) int {
		t.Helper()
		return count(t, `SELECT count(*) FROM information_schema.columns
		      WHERE table_name = $1 AND column_name = ANY($2)`, table, names)
	}
	hasConstraint := func(t *testing.T, name string) bool {
		t.Helper()
		return count(t, `SELECT count(*) FROM pg_constraint WHERE conname = $1`, name) == 1
	}
	hasTrigger := func(t *testing.T) bool {
		t.Helper()
		return count(t, `SELECT count(*) FROM pg_trigger WHERE tgname = 'oauth_tokens_fill_resource'`)+
			count(t, `SELECT count(*) FROM pg_proc WHERE proname = 'oauth_tokens_fill_resource'`) == 2
	}
	hasFamilyIndex := func(t *testing.T) bool {
		t.Helper()
		return count(t, `SELECT count(*) FROM pg_indexes
		      WHERE tablename = 'oauth_tokens' AND indexname = 'idx_oauth_tokens_family_id'`) == 1
	}
	tokenResource := func(t *testing.T, refresh string) sql.NullString {
		t.Helper()
		return queryString(t, `SELECT resource FROM oauth_tokens WHERE refresh_token = $1`, refresh)
	}

	const oldConsentKey = "oauth_user_consents_user_id_client_id_key"
	mfaFieldColumns := []string{"client_id", "redirect_uri", "state", "scope", "code_challenge", "code_challenge_method", "nonce"}

	// Version 11: the world before 000012.
	require.NoError(t, m.Migrate(11))
	exec(t, `INSERT INTO oauth_clients (client_id, name, redirect_uris, allowed_scopes, is_confidential, audience)
	      VALUES ('footstrike', 'Footstrike Dashboard', '{https://app.example/cb}', '{openid}', false, 'ethanswan:fitness'),
	             ('no-audience', 'No Audience', '{https://app.example/cb}', '{openid}', false, '')`)
	exec(t, `INSERT INTO auth_users (username, password_hash, email) VALUES ('u', 'x', 'u@example.com')`)
	userID := queryString(t, `SELECT id::text FROM auth_users WHERE username = 'u'`).String
	insertTokenWithoutResource := func(t *testing.T, refresh, clientID string) {
		t.Helper()
		exec(t, `INSERT INTO oauth_tokens (access_token, refresh_token, user_id, client_id, scope, expires_at)
		      VALUES ($1, $1, $2, $3, '{openid}', now() + interval '1 hour')`, refresh, userID, clientUUID(t, clientID))
	}
	insertTokenWithoutResource(t, "tok-pre-12", "footstrike")
	exec(t, `INSERT INTO oauth_user_consents (user_id, client_id, scopes) VALUES ($1, $2, '{openid}')`,
		userID, clientUUID(t, "footstrike"))

	// Version 13: the rollout window. The previous release's writes name the
	// old columns and none of the new ones.
	require.NoError(t, m.Migrate(13))
	insertTokenWithoutResource(t, "tok-old-release", "footstrike")
	require.Equal(t, sql.NullString{String: "ethanswan:fitness", Valid: true}, tokenResource(t, "tok-old-release"),
		"precondition: the trigger fills what the previous release left out")
	exec(t, `INSERT INTO auth_mfa_pending (id, user_id, client_id, redirect_uri, state, scope, code_challenge, code_challenge_method, nonce, expires_at)
	      VALUES ('mfa-old', $1, 'footstrike', 'https://app.example/cb', 's', '{openid}', 'c', 'S256', 'n', now() + interval '5 minutes')`, userID)
	// ...and this release's.
	exec(t, `INSERT INTO auth_mfa_pending (id, user_id, authorize_query, expires_at)
	      VALUES ('mfa-new', $1, 'client_id=footstrike&state=s', now() + interval '5 minutes')`, userID)
	exec(t, `INSERT INTO oauth_tokens (access_token, refresh_token, user_id, client_id, scope, expires_at, resource, family_id)
	      VALUES ('tok-new', 'tok-new', $1, $2, '{openid}', now() + interval '1 hour', 'https://identity.example', gen_random_uuid())`,
		userID, clientUUID(t, "no-audience"))

	t.Run("up drops what the old releases used and keeps the data", func(t *testing.T) {
		require.NoError(t, m.Migrate(14))

		require.Equal(t, 0, columns(t, "oauth_clients", "audience"))
		require.Equal(t, sql.NullString{String: "ethanswan:fitness", Valid: true},
			queryString(t, `SELECT default_resource FROM oauth_clients WHERE client_id = 'footstrike'`))

		require.False(t, hasTrigger(t), "the fill trigger and its function are dropped")
		require.Equal(t, sql.NullString{String: "ethanswan:fitness", Valid: true}, tokenResource(t, "tok-pre-12"),
			"000012's backfill stays")
		require.Equal(t, sql.NullString{String: "ethanswan:fitness", Valid: true}, tokenResource(t, "tok-old-release"),
			"what the trigger filled stays")
		require.Equal(t, sql.NullString{String: "https://identity.example", Valid: true}, tokenResource(t, "tok-new"))
		insertTokenWithoutResource(t, "tok-null", "footstrike")
		require.False(t, tokenResource(t, "tok-null").Valid, "no trigger: a NULL resource stays NULL")
		require.Equal(t, "YES", queryString(t, `SELECT is_nullable FROM information_schema.columns
		      WHERE table_name = 'oauth_tokens' AND column_name = 'resource'`).String, "resource stays nullable")

		require.Equal(t, 0, columns(t, "auth_mfa_pending", mfaFieldColumns...))
		require.Equal(t, 2, count(t, `SELECT count(*) FROM auth_mfa_pending`))
		require.Equal(t, "client_id=footstrike&state=s",
			queryString(t, `SELECT authorize_query FROM auth_mfa_pending WHERE id = 'mfa-new'`).String)

		require.True(t, hasFamilyIndex(t))

		// Consent: the old (user, client) key is gone, the (user, client,
		// resource) one stays, NULL counting as a value.
		require.False(t, hasConstraint(t, oldConsentKey))
		exec(t, `INSERT INTO oauth_user_consents (user_id, client_id, scopes, resource) VALUES ($1, $2, '{openid}', 'ethanswan:fitness')`,
			userID, clientUUID(t, "footstrike"))
		require.Equal(t, 2, count(t, `SELECT count(*) FROM oauth_user_consents`),
			"one consent per resource for the same user and client")
		_, err := conn.ExecContext(ctx, `INSERT INTO oauth_user_consents (user_id, client_id, scopes) VALUES ($1, $2, '{openid}')`,
			userID, clientUUID(t, "footstrike"))
		require.Error(t, err, "a second no-resource consent for the same user and client must still conflict")
		_, err = conn.ExecContext(ctx, `INSERT INTO oauth_user_consents (user_id, client_id, scopes, resource) VALUES ($1, $2, '{openid}', 'ethanswan:fitness')`,
			userID, clientUUID(t, "footstrike"))
		require.Error(t, err, "and so must a second consent for the same resource")

	})

	t.Run("down restores version 13's schema", func(t *testing.T) {
		require.NoError(t, m.Migrate(13))

		require.False(t, hasFamilyIndex(t))
		require.Equal(t, len(mfaFieldColumns), columns(t, "auth_mfa_pending", mfaFieldColumns...))
		require.Equal(t, 0, count(t, `SELECT count(*) FROM information_schema.columns
		      WHERE table_name = 'auth_mfa_pending' AND column_name = ANY($1) AND is_nullable = 'NO'`, mfaFieldColumns))
		require.Equal(t, 2, count(t, `SELECT count(*) FROM auth_mfa_pending`))

		require.True(t, hasTrigger(t))
		insertTokenWithoutResource(t, "tok-old-release-again", "footstrike")
		require.Equal(t, sql.NullString{String: "ethanswan:fitness", Valid: true}, tokenResource(t, "tok-old-release-again"))

		require.True(t, hasConstraint(t, oldConsentKey))
		require.Equal(t, 1, count(t, `SELECT count(*) FROM oauth_user_consents`),
			"the per-resource consent is gone; the no-resource one stays")
		require.Equal(t, 0, count(t, `SELECT count(*) FROM oauth_user_consents WHERE resource IS NOT NULL`))
		// The previous release's upsert names the old key in ON CONFLICT.
		exec(t, `INSERT INTO oauth_user_consents (user_id, client_id, scopes) VALUES ($1, $2, '{openid,profile}')
		      ON CONFLICT (user_id, client_id) DO UPDATE SET scopes = EXCLUDED.scopes`, userID, clientUUID(t, "footstrike"))

		require.Equal(t, "YES", queryString(t, `SELECT is_nullable FROM information_schema.columns
		      WHERE table_name = 'oauth_clients' AND column_name = 'audience'`).String)
		require.Equal(t, sql.NullString{String: "ethanswan:fitness", Valid: true},
			queryString(t, `SELECT audience FROM oauth_clients WHERE client_id = 'footstrike'`))
		require.False(t, queryString(t, `SELECT audience FROM oauth_clients WHERE client_id = 'no-audience'`).Valid)
	})

	t.Run("further down through 000012's down", func(t *testing.T) {
		require.NoError(t, m.Migrate(11))
		require.Equal(t, "ethanswan:fitness", queryString(t, `SELECT audience FROM oauth_clients WHERE client_id = 'footstrike'`).String)
		require.Equal(t, "", queryString(t, `SELECT audience FROM oauth_clients WHERE client_id = 'no-audience'`).String)
	})

	t.Run("up again", func(t *testing.T) {
		require.NoError(t, m.Migrate(14))
		require.Equal(t, 0, columns(t, "oauth_clients", "audience"))
		require.Equal(t, 0, columns(t, "auth_mfa_pending", mfaFieldColumns...))
		require.False(t, hasTrigger(t))
		require.False(t, hasConstraint(t, oldConsentKey))
		require.True(t, hasFamilyIndex(t))
		require.Equal(t, sql.NullString{String: "ethanswan:fitness", Valid: true}, tokenResource(t, "tok-old-release"))
	})
}
