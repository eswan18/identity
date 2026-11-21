package internal

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// stubSecret replaces AccessSecret for one test, recording the names asked for.
func stubSecret(t *testing.T, value string, err error) *[]string {
	t.Helper()
	var asked []string
	orig := AccessSecret
	AccessSecret = func(_ context.Context, name string) (string, error) {
		asked = append(asked, name)
		return value, err
	}
	t.Cleanup(func() { AccessSecret = orig })
	return &asked
}

func TestResolveTargetStaging(t *testing.T) {
	asked := stubSecret(t, "postgres://u:pw@staging.example/db", nil)
	tg, err := ResolveTarget(context.Background(), "staging", "", false)
	require.NoError(t, err)
	require.Equal(t, []string{"identity_staging_database_url"}, *asked)
	require.Equal(t, "staging", tg.Name)
	require.False(t, tg.IsProd())
	require.Equal(t, "postgres://u:pw@staging.example/db", tg.URL)
}

func TestResolveTargetProdDescribeHidesPassword(t *testing.T) {
	stubSecret(t, "postgres://u:secret@h.example/db\n", nil)
	tg, err := ResolveTarget(context.Background(), "prod", "", true)
	require.NoError(t, err)
	require.True(t, tg.IsProd())
	require.Equal(t, "postgres://u:secret@h.example/db", tg.URL, "the trailing newline is trimmed")
	d := tg.Describe()
	require.Contains(t, d, "identity_prod_database_url")
	require.Contains(t, d, "h.example")
	require.NotContains(t, d, "secret@")
	require.NotContains(t, d, ":secret")
}

func TestResolveTargetRejectsUnknownEnv(t *testing.T) {
	stubSecret(t, "unused", nil)
	_, err := ResolveTarget(context.Background(), "dev", "", true)
	require.ErrorContains(t, err, "staging or prod")
}

func TestResolveTargetEnvAndURLExclusive(t *testing.T) {
	stubSecret(t, "unused", nil)
	_, err := ResolveTarget(context.Background(), "prod", "postgres://x/y", true)
	require.Error(t, err)
}

func TestResolveTargetCustomURL(t *testing.T) {
	tg, err := ResolveTarget(context.Background(), "", "postgres://u:p@local.example:5432/db", false)
	require.NoError(t, err)
	require.Equal(t, "custom", tg.Name)
	require.False(t, tg.IsProd())
	require.Equal(t, "local.example", tg.Host())
}

func TestResolveTargetLegacyDatabaseURL(t *testing.T) {
	t.Setenv("ENV", "")
	t.Setenv("DATABASE_URL", "postgres://u:p@legacy.example/db")
	tg, err := ResolveTarget(context.Background(), "", "", true)
	require.NoError(t, err)
	require.Equal(t, "ENV=local", tg.Name)
	require.Equal(t, "postgres://u:p@legacy.example/db", tg.URL)
	require.False(t, tg.IsProd())
}

func TestResolveTargetNoSourceWithoutLegacy(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://u:p@legacy.example/db")
	_, err := ResolveTarget(context.Background(), "", "", false)
	require.Error(t, err, "without legacy, DATABASE_URL is ignored")
}

func TestResolveTargetGcloudMissing(t *testing.T) {
	stubSecret(t, "", exec.ErrNotFound)
	_, err := ResolveTarget(context.Background(), "staging", "", true)
	require.ErrorContains(t, err, "gcloud")
}

func TestResolveTargetGcloudNotLoggedIn(t *testing.T) {
	stubSecret(t, "", &exec.ExitError{})
	_, err := ResolveTarget(context.Background(), "staging", "", true)
	require.ErrorContains(t, err, "gcloud auth login")
}

func TestResolveTargetEmptySecret(t *testing.T) {
	stubSecret(t, "  \n", nil)
	_, err := ResolveTarget(context.Background(), "staging", "", true)
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "empty") || errors.Is(err, errEmptySecret))
}
