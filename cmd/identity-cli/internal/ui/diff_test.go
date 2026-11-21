package ui

import (
	"database/sql"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/eswan18/identity/cmd/identity-cli/internal/ops"
	"github.com/eswan18/identity/pkg/db"
	"github.com/stretchr/testify/require"
)

func TestParseLines(t *testing.T) {
	require.Equal(t, []string{"a", "b"}, ParseLines("a\n\n b ,a\r\n"))
	require.Equal(t, []string{}, ParseLines("  \n\t"))
	require.Equal(t, []string{"openid", "profile"}, ParseLines("openid profile"), "scopes may be space-separated")
}

func detail() ops.ClientDetail {
	return ops.ClientDetail{
		Client: db.OauthClient{
			Name:          "App",
			RedirectUris:  []string{"https://a.example/cb", "https://b.example/cb"},
			AllowedScopes: []string{"openid"},
			Kind:          "registered",
		},
		Resources: []db.OauthResource{{Uri: "https://r1.example"}},
	}
}

func TestBuildClientUpdateUnchangedFormIsNoChange(t *testing.T) {
	cur := detail()
	f := clientForm{
		Name:         "App",
		RedirectURIs: []string{"https://b.example/cb", "https://a.example/cb"}, // order alone is not a change
		Scopes:       []string{"openid"},
		Resources:    []string{"https://r1.example"},
	}
	u := buildClientUpdate(cur, f)
	require.Empty(t, DiffClient(cur, u))
	require.Nil(t, u.Name)
	require.Equal(t, ops.Keep, u.RedirectURIs.Mode)
	require.Equal(t, ops.Keep, u.Resources.Mode)
	require.Nil(t, u.DefaultResource)
	require.Nil(t, u.Trusted)
}

func TestDiffClient(t *testing.T) {
	cur := detail()
	f := clientForm{
		Name:            "Renamed",
		RedirectURIs:    []string{"https://b.example/cb", "https://c.example/cb"},
		Scopes:          []string{"openid"},
		Resources:       []string{},
		DefaultResource: "https://r1.example",
		Trusted:         true,
	}
	changes := DiffClient(cur, buildClientUpdate(cur, f))

	byField := map[string]Change{}
	for _, c := range changes {
		byField[c.Field] = c
	}
	require.Equal(t, Change{Field: "Name", Before: "App", After: "Renamed"}, byField["Name"])
	require.Equal(t, []string{"https://c.example/cb"}, byField["Redirect URIs"].Added)
	require.Equal(t, []string{"https://a.example/cb"}, byField["Redirect URIs"].Removed)
	require.Equal(t, []string{"https://r1.example"}, byField["Allowed resources"].Removed)
	require.Equal(t, "(identity itself)", byField["Default resource"].Before)
	require.Equal(t, "https://r1.example", byField["Default resource"].After)
	require.Equal(t, Change{Field: "Trusted", Before: "no", After: "yes"}, byField["Trusted"])
	require.NotContains(t, byField, "Scopes")
}

func TestBuildClientUpdateClearsDefault(t *testing.T) {
	cur := detail()
	cur.Client.DefaultResource = sql.NullString{String: "https://r1.example", Valid: true}
	f := clientForm{Name: "App", RedirectURIs: cur.Client.RedirectUris, Scopes: []string{"openid"}, Resources: []string{"https://r1.example"}}
	u := buildClientUpdate(cur, f)
	require.NotNil(t, u.DefaultResource)
	require.Equal(t, "", *u.DefaultResource)
}

func resDetail() ops.ResourceDetail {
	return ops.ResourceDetail{
		Resource: db.OauthResource{Uri: "https://r.example", Name: "R"},
		Scopes:   map[string]string{"r:read": "Read R", "r:write": "Write R"},
	}
}

func TestDiffResource(t *testing.T) {
	cur := resDetail()
	f := resourceForm{
		Name:           "R",
		Scopes:         map[string]string{"r:read": "Read all of R", "r:admin": "Manage R"},
		DynamicClients: true,
	}
	changes := DiffResource(cur, buildResourceUpdate(cur, f))
	byField := map[string]Change{}
	for _, c := range changes {
		byField[c.Field] = c
	}
	require.NotContains(t, byField, "Name")
	require.ElementsMatch(t, []string{"r:admin: Manage R", "r:read: Read all of R"}, byField["Scopes"].Added)
	require.ElementsMatch(t, []string{"r:read: Read R", "r:write: Write R"}, byField["Scopes"].Removed)
	require.Equal(t, Change{Field: "Dynamic clients", Before: "no", After: "yes"}, byField["Dynamic clients"])
}

func TestBuildResourceUpdateUnchanged(t *testing.T) {
	cur := resDetail()
	u := buildResourceUpdate(cur, resourceForm{Name: "R", Scopes: map[string]string{"r:write": "Write R", "r:read": "Read R"}})
	require.Empty(t, DiffResource(cur, u))
	require.Equal(t, ops.Keep, u.Scopes.Mode)
}

func TestParseResourceFormKeepsInputOnError(t *testing.T) {
	req := httptest.NewRequest("POST", "/", strings.NewReader(url.Values{
		"name":            {"My API"},
		"scope_name":      {"a:read", "a:read"},
		"scope_desc":      {"Read A", "Read A again"},
		"dynamic_clients": {"on"},
		"fingerprint":     {"fp"},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	require.NoError(t, req.ParseForm())
	f, err := parseResourceForm(req)
	require.ErrorContains(t, err, "listed twice")
	require.Equal(t, "My API", f.Name, "the operator's input survives the error")
	require.True(t, f.DynamicClients)
	require.Equal(t, "fp", f.Fingerprint)
	require.Equal(t, map[string]string{"a:read": "Read A"}, f.Scopes)
}
