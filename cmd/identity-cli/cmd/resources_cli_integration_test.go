//go:build integration

package cmd

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"

	"github.com/eswan18/identity/db/migrations"
	"github.com/eswan18/identity/pkg/db"
	"github.com/eswan18/identity/pkg/store"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

// testJWTPrivateKey is the key CI and the httpserver tests use; it is only
// for tests.
const testJWTPrivateKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEICQMNHONu2Sud2tu6jgOZs3LIj5yOZr89NBMLYiyqBK/oAoGCCqGSM49
AwEHoUQDQgAERCHWHrX20emk31HypGNgptwBjdZOyBybV/9BLTbJPj8UsZ/46ri5
/eFKkRfNApxFU/5lk1RGQJqt8t0GvkkJdw==
-----END EC PRIVATE KEY-----`

// TestCLIResourcesAndAllowLists drives identity-cli's resource commands and
// client allow-list flags against a real, migrated database, the way an
// operator would: through the command line, checking what landed in the
// database.
func TestCLIResourcesAndAllowLists(t *testing.T) {
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
	require.NoError(t, migrations.Up(dbURL))
	// The CLI connects through config.NewFromEnv, which insists on the whole
	// service configuration even though it only uses DATABASE_URL.
	t.Setenv("DATABASE_URL", dbURL)
	t.Setenv("HTTP_ADDRESS", ":0")
	t.Setenv("JWT_ISSUER", "http://localhost:8080")
	t.Setenv("JWT_PRIVATE_KEY", testJWTPrivateKey)

	ds, err := store.New(dbURL)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ds.DB.Close() })
	q := ds.Q

	cli := func(args ...string) error {
		t.Helper()
		resetFlags(rootCmd)
		rootCmd.SilenceUsage = true
		rootCmd.SilenceErrors = true
		rootCmd.SetArgs(args)
		return rootCmd.Execute()
	}
	mustCLI := func(args ...string) {
		t.Helper()
		require.NoError(t, cli(args...), "identity-cli %v", args)
	}
	resource := func(uri string) db.OauthResource {
		t.Helper()
		r, err := q.GetOAuthResourceByURI(ctx, uri)
		require.NoError(t, err)
		return r
	}
	scopes := func(r db.OauthResource) map[string]string {
		t.Helper()
		var m map[string]string
		require.NoError(t, json.Unmarshal(r.Scopes, &m))
		return m
	}
	clientNamed := func(name string) db.OauthClient {
		t.Helper()
		clients, err := q.ListOAuthClients(ctx)
		require.NoError(t, err)
		for _, c := range clients {
			if c.Name == name {
				return c
			}
		}
		t.Fatalf("no client named %s", name)
		return db.OauthClient{}
	}
	allowList := func(c db.OauthClient) []string {
		t.Helper()
		rs, err := q.ListClientResources(ctx, c.ID)
		require.NoError(t, err)
		uris := []string{}
		for _, r := range rs {
			uris = append(uris, r.Uri)
		}
		return uris
	}

	const a, b = "https://a.example.com/mcp", "https://b.example.com/mcp"

	// resource create stores the canonical URI.
	mustCLI("resource", "create", "--uri", "HTTPS://A.Example.com/mcp/", "--name", "A", "--scope", "a:read=Read A")
	mustCLI("resource", "create", "--uri", b, "--name", "B", "--scope", "b:read=Read B")
	require.Equal(t, map[string]string{"a:read": "Read A"}, scopes(resource(a)))
	require.Error(t, cli("resource", "create", "--uri", "http://insecure.example.com", "--name", "X"), "https is required")
	mustCLI("resource", "list")
	mustCLI("resource", "get", a)

	// resource update: each flag, and nothing else, changes.
	mustCLI("resource", "update", a, "--add-scope", "a:write=Write A")
	require.Equal(t, map[string]string{"a:read": "Read A", "a:write": "Write A"}, scopes(resource(a)))
	require.Error(t, cli("resource", "update", a, "--remove-scope", "a:typo"))
	require.Len(t, scopes(resource(a)), 2, "a refused removal changes nothing")
	mustCLI("resource", "update", a, "--remove-scope", "a:write")
	require.Equal(t, map[string]string{"a:read": "Read A"}, scopes(resource(a)))
	mustCLI("resource", "update", a, "--name", "A Renamed", "--dynamic-clients=true")
	require.Equal(t, "A Renamed", resource(a).Name)
	require.True(t, resource(a).DynamicClients)
	require.Equal(t, map[string]string{"a:read": "Read A"}, scopes(resource(a)), "untouched by --name")
	mustCLI("resource", "update", a, "--scope", "a:all=Everything in A")
	require.Equal(t, map[string]string{"a:all": "Everything in A"}, scopes(resource(a)), "--scope replaces the set")
	require.Error(t, cli("resource", "update", a, "--add-scope", "openid=Sign in"), "identity's scopes can't belong to a resource")
	require.Error(t, cli("resource", "update", "https://unknown.example.com", "--name", "X"))

	// client create --resources sets the allow-list, any spelling of the URI.
	mustCLI("client", "create", "--name", "CLI Client", "--redirect-uris", "http://localhost/callback",
		"--scopes", "a:all", "--resources", "HTTPS://a.example.com/mcp")
	client := clientNamed("CLI Client")
	require.Equal(t, []string{a}, allowList(client))
	require.Error(t, cli("client", "create", "--name", "Bad", "--redirect-uris", "http://localhost/callback",
		"--resources", "https://unknown.example.com"))
	clients, err := q.ListOAuthClients(ctx)
	require.NoError(t, err)
	require.Len(t, clients, 1, "a refused create leaves no client behind")

	// client update: add, remove, replace.
	mustCLI("client", "update", client.ClientID, "--add-resources", b)
	require.Equal(t, []string{a, b}, allowList(client))
	require.Error(t, cli("client", "update", client.ClientID, "--remove-resources", b+","+"https://a.example.com/other"),
		"an unknown resource is refused")
	require.Equal(t, []string{a, b}, allowList(client))
	mustCLI("client", "update", client.ClientID, "--remove-resources", b)
	require.Equal(t, []string{a}, allowList(client))
	require.Error(t, cli("client", "update", client.ClientID, "--remove-resources", b, "--name", "Renamed"),
		"removing one it doesn't have is an error")
	require.Equal(t, "CLI Client", clientNamed("CLI Client").Name, "and the whole update is rolled back")
	mustCLI("client", "update", client.ClientID, "--resources", b)
	require.Equal(t, []string{b}, allowList(client))
	mustCLI("client", "update", client.ClientID, "--resources", "")
	require.Equal(t, []string{}, allowList(client))
	mustCLI("client", "get", client.ClientID)
	mustCLI("client", "list")

	// resource delete refuses while a client names it, either way.
	mustCLI("client", "update", client.ClientID, "--default-resource", a, "--add-resources", b)
	require.Error(t, cli("resource", "delete", a, "--force"), "a client's default")
	require.Error(t, cli("resource", "delete", b, "--force"), "on a client's allow-list")
	resource(a)
	resource(b)
	mustCLI("client", "update", client.ClientID, "--clear-default-resource", "--remove-resources", b)
	mustCLI("resource", "delete", a, "--force")
	mustCLI("resource", "delete", b, "--force")
	_, err = q.GetOAuthResourceByURI(ctx, a)
	require.ErrorIs(t, err, sql.ErrNoRows)
	_, err = q.GetOAuthResourceByURI(ctx, b)
	require.ErrorIs(t, err, sql.ErrNoRows)
}

// TestCLITrustedClients drives --trusted on client create and update against
// a real, migrated database: it defaults to untrusted, can be set and unset,
// is shown by get and list, and is refused for a metadata-document client.
func TestCLITrustedClients(t *testing.T) {
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
	require.NoError(t, migrations.Up(dbURL))
	t.Setenv("DATABASE_URL", dbURL)
	t.Setenv("HTTP_ADDRESS", ":0")
	t.Setenv("JWT_ISSUER", "http://localhost:8080")
	t.Setenv("JWT_PRIVATE_KEY", testJWTPrivateKey)

	ds, err := store.New(dbURL)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ds.DB.Close() })
	q := ds.Q

	cli := func(args ...string) error {
		t.Helper()
		resetFlags(rootCmd)
		rootCmd.SilenceUsage = true
		rootCmd.SilenceErrors = true
		rootCmd.SetArgs(args)
		return rootCmd.Execute()
	}
	mustCLI := func(args ...string) {
		t.Helper()
		require.NoError(t, cli(args...), "identity-cli %v", args)
	}
	clientNamed := func(name string) db.OauthClient {
		t.Helper()
		clients, err := q.ListOAuthClients(ctx)
		require.NoError(t, err)
		for _, c := range clients {
			if c.Name == name {
				return c
			}
		}
		t.Fatalf("no client named %s", name)
		return db.OauthClient{}
	}

	// Untrusted unless asked.
	mustCLI("client", "create", "--name", "Third Party", "--redirect-uris", "https://third.example/cb")
	require.False(t, clientNamed("Third Party").Trusted, "the default is untrusted")

	// create --trusted.
	mustCLI("client", "create", "--name", "First Party", "--redirect-uris", "https://app.example/cb", "--trusted")
	first := clientNamed("First Party")
	require.True(t, first.Trusted)
	mustCLI("client", "get", first.ClientID)
	mustCLI("client", "list")

	// update --trusted=false / --trusted=true; other updates leave it alone.
	mustCLI("client", "update", first.ClientID, "--trusted=false")
	require.False(t, clientNamed("First Party").Trusted)
	mustCLI("client", "update", first.ClientID, "--trusted=true")
	require.True(t, clientNamed("First Party").Trusted)
	mustCLI("client", "update", first.ClientID, "--name", "First Party Renamed")
	require.True(t, clientNamed("First Party Renamed").Trusted, "an update without --trusted keeps it")

	// A metadata-document client can never be trusted; the CLI says so and
	// changes nothing (the other flags in the same command included).
	const cimdURL = "https://claude.ai/oauth/claude-code-client-metadata"
	_, err = q.CreateCIMDClient(ctx, db.CreateCIMDClientParams{
		ClientID:     cimdURL,
		Name:         "Claude",
		RedirectUris: []string{"https://claude.ai/api/mcp/auth_callback"},
	})
	require.NoError(t, err)
	err = cli("client", "update", cimdURL, "--trusted=true", "--name", "Sneaky")
	require.ErrorContains(t, err, "refusing to trust")
	cimdClient, err := q.GetOAuthClientByClientID(ctx, cimdURL)
	require.NoError(t, err)
	require.False(t, cimdClient.Trusted)
	require.Equal(t, "Claude", cimdClient.Name, "a refused update changes nothing")
	mustCLI("client", "update", cimdURL, "--trusted=false")

	// The database refuses it too, whatever path writes the row.
	_, err = q.UpdateOAuthClient(ctx, db.UpdateOAuthClientParams{
		ClientID: cimdURL,
		Trusted:  sql.NullBool{Bool: true, Valid: true},
	})
	require.Error(t, err, "the CHECK constraint refuses a trusted metadata-document client")
}

// resetFlags returns every flag of cmd and its subcommands to its default and
// marks it unchanged. The commands are package-level and keep flag values
// between Execute calls, so without this one invocation's flags would leak
// into the next.
func resetFlags(cmd *cobra.Command) {
	reset := func(f *pflag.Flag) {
		if sv, ok := f.Value.(pflag.SliceValue); ok {
			_ = sv.Replace(nil)
		} else {
			_ = f.Value.Set(f.DefValue)
		}
		f.Changed = false
	}
	cmd.Flags().VisitAll(reset)
	cmd.PersistentFlags().VisitAll(reset)
	for _, c := range cmd.Commands() {
		resetFlags(c)
	}
}
