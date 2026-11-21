//go:build integration

package ops

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/eswan18/identity/db/migrations"
	"github.com/eswan18/identity/pkg/db"
	"github.com/eswan18/identity/pkg/store"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

// newStore starts a migrated Postgres and returns a store on it.
func newStore(t *testing.T) *store.Store {
	t.Helper()
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
	s, err := store.New(dbURL)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.DB.Close() })
	return s
}

func ptr[T any](v T) *T { return &v }

func TestCLIOps(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	const a, b = "https://a.example.com/mcp", "https://b.example.com/mcp"
	_, err := CreateResource(ctx, s, a, "A", map[string]string{"a:read": "Read A"}, false)
	require.NoError(t, err)
	_, err = CreateResource(ctx, s, b, "B", map[string]string{"b:read": "Read B"}, false)
	require.NoError(t, err)

	t.Run("StaleClientUpdate", func(t *testing.T) {
		c, _, err := CreateClient(ctx, s, ClientCreate{Name: "Stale", RedirectURIs: []string{"https://s.example/cb"}, Scopes: []string{"openid"}})
		require.NoError(t, err)
		fp := c.Fingerprint()

		// The allow-list changes behind the reviewer's back; updated_at does not.
		res, err := s.Q.GetOAuthResourceByURI(ctx, a)
		require.NoError(t, err)
		require.NoError(t, s.Q.AddClientResource(ctx, db.AddClientResourceParams{ClientID: c.Client.ID, ResourceID: res.ID}))

		_, err = UpdateClient(ctx, s, c.Client.ClientID, ClientUpdate{Name: ptr("Renamed"), ExpectFingerprint: fp})
		require.True(t, errors.Is(err, ErrStale), "got %v", err)
		got, err := GetClient(ctx, s, c.Client.ClientID)
		require.NoError(t, err)
		require.Equal(t, "Stale", got.Client.Name, "a stale update writes nothing")
	})

	t.Run("StaleResourceUpdate", func(t *testing.T) {
		r, err := GetResource(ctx, s, b)
		require.NoError(t, err)
		fp := r.Fingerprint()

		_, err = s.Q.UpdateOAuthResource(ctx, db.UpdateOAuthResourceParams{
			Uri: b, Name: "B", Scopes: json.RawMessage(`{"b:read":"Read B, changed"}`),
		})
		require.NoError(t, err)

		_, err = UpdateResource(ctx, s, b, ResourceUpdate{Name: ptr("B2"), ExpectFingerprint: fp})
		require.True(t, errors.Is(err, ErrStale), "got %v", err)
		got, err := GetResource(ctx, s, b)
		require.NoError(t, err)
		require.Equal(t, "B", got.Resource.Name)
	})

	t.Run("ClientUpdateReplaceAll", func(t *testing.T) {
		c, _, err := CreateClient(ctx, s, ClientCreate{
			Name: "Replace", RedirectURIs: []string{"https://r.example/1", "https://r.example/2"},
			Scopes: []string{"openid"}, Resources: []string{a},
		})
		require.NoError(t, err)
		got, err := UpdateClient(ctx, s, c.Client.ClientID, ClientUpdate{
			RedirectURIs:      ListEdit{Mode: Replace, Values: []string{"https://r.example/2", "https://r.example/3"}},
			Resources:         ListEdit{Mode: Replace, Values: []string{b}},
			ExpectFingerprint: c.Fingerprint(),
		})
		require.NoError(t, err)
		require.Equal(t, []string{"https://r.example/2", "https://r.example/3"}, got.Client.RedirectUris)
		require.Len(t, got.Resources, 1)
		require.Equal(t, b, got.Resources[0].Uri)
	})

	t.Run("TrustRules", func(t *testing.T) {
		c, _, err := CreateClient(ctx, s, ClientCreate{Name: "Trust", RedirectURIs: []string{"https://t.example/cb"}, Scopes: []string{"openid"}})
		require.NoError(t, err)
		_, err = UpdateClient(ctx, s, c.Client.ClientID, ClientUpdate{
			Trusted:      ptr(true),
			RedirectURIs: ListEdit{Mode: Add, Values: []string{"https://*.preview.example.com/cb"}},
		})
		require.ErrorContains(t, err, "wildcard")
		got, err := GetClient(ctx, s, c.Client.ClientID)
		require.NoError(t, err)
		require.False(t, got.Client.Trusted)
		require.Equal(t, []string{"https://t.example/cb"}, got.Client.RedirectUris)

		_, _, err = CreateClient(ctx, s, ClientCreate{Name: "Loop", RedirectURIs: []string{"http://localhost/cb"}, Trusted: true})
		require.ErrorContains(t, err, "loopback")
	})

	t.Run("DeleteResourceInUse", func(t *testing.T) {
		_, _, err := CreateClient(ctx, s, ClientCreate{Name: "User Of A", RedirectURIs: []string{"https://u.example/cb"}, DefaultResource: a})
		require.NoError(t, err)
		err = DeleteResource(ctx, s, a)
		require.ErrorContains(t, err, "User Of A")
		_, err = GetResource(ctx, s, a)
		require.NoError(t, err, "still there")
	})
}
