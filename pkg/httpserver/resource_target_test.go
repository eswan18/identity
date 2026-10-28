package httpserver

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eswan18/identity/pkg/config"
	"github.com/eswan18/identity/pkg/db"
)

func TestRequestedResource(t *testing.T) {
	cases := []struct {
		name        string
		values      []string
		wantURI     string
		wantPresent bool
		wantErr     bool
	}{
		{"absent", nil, "", false, false},
		{"canonical", []string{"https://sensibility.money/mcp"}, "https://sensibility.money/mcp", true, false},
		{"canonicalized", []string{"HTTPS://Sensibility.money/mcp/"}, "https://sensibility.money/mcp", true, false},
		{"urn kept", []string{"ethanswan:fitness"}, "ethanswan:fitness", true, false},
		{"two values", []string{"https://a.example", "https://b.example"}, "", true, true},
		{"two equal values", []string{"https://a.example", "https://a.example"}, "", true, true},
		{"empty", []string{""}, "", true, true},
		{"relative", []string{"/mcp"}, "", true, true},
		{"fragment", []string{"https://a.example/mcp#x"}, "", true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, present, oauthErr := requestedResource(c.values)
			if present != c.wantPresent {
				t.Errorf("present = %v, want %v", present, c.wantPresent)
			}
			if c.wantErr {
				if oauthErr == nil || oauthErr.Code != "invalid_target" {
					t.Errorf("error = %+v, want invalid_target", oauthErr)
				}
				return
			}
			if oauthErr != nil || got != c.wantURI {
				t.Errorf("= %q, %+v; want %q", got, oauthErr, c.wantURI)
			}
		})
	}
}

func TestSameResource(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"https://a.example/mcp", "https://a.example/mcp", true},
		{"https://a.example/mcp", "HTTPS://A.example:443/mcp/", true},
		// A backfilled URI that predates the canonical form still matches its
		// canonical spelling.
		{"https://Shared.Example/api/", "https://shared.example/api", true},
		{"ethanswan:fitness", "ethanswan:fitness", true},
		{"https://a.example/mcp", "https://a.example/MCP", false},
		{"https://a.example/mcp", "https://b.example/mcp", false},
		{"ethanswan:fitness", "https://a.example", false},
	}
	for _, c := range cases {
		if got := sameResource(c.a, c.b); got != c.want {
			t.Errorf("sameResource(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestCheckScopesAgainstResource(t *testing.T) {
	sensibility := &resolvedResource{
		URI:    "https://sensibility.money/mcp",
		Name:   "Sensibility",
		Scopes: map[string]string{"sensibility:read": "Read", "sensibility:write": "Write"},
	}
	cases := []struct {
		name     string
		scope    []string
		resource *resolvedResource
		wantErr  bool
	}{
		{"identity scopes, no resource", []string{"openid", "profile", "email", "offline_access"}, nil, false},
		{"identity scopes, with a resource", []string{"openid"}, sensibility, false},
		{"resource scopes", []string{"sensibility:read", "offline_access"}, sensibility, false},
		{"resource scope without a resource", []string{"openid", "sensibility:read"}, nil, true},
		{"scope the resource doesn't define", []string{"sensibility:admin"}, sensibility, true},
		{"empty scope string", []string{""}, sensibility, true},
		// Admin scopes are identity's; validateAuthorizeParams refuses them on
		// this flow, not the registry check.
		{"admin scope left to the other check", []string{"admin:users:read"}, nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkScopesAgainstResource(c.scope, c.resource)
			if c.wantErr != (err != nil) {
				t.Fatalf("error = %+v, want error %v", err, c.wantErr)
			}
			if err != nil && err.Code != "invalid_scope" {
				t.Errorf("code = %q, want invalid_scope", err.Code)
			}
		})
	}
}

func TestCheckTokenRequestResource(t *testing.T) {
	granted := sql.NullString{String: "https://sensibility.money/mcp", Valid: true}
	none := sql.NullString{}
	cases := []struct {
		name    string
		values  []string
		granted sql.NullString
		wantOK  bool
	}{
		{"absent", nil, granted, true},
		{"absent, no resource", nil, none, true},
		{"same", []string{"https://sensibility.money/mcp"}, granted, true},
		{"same, other spelling", []string{"HTTPS://Sensibility.money/mcp/"}, granted, true},
		{"different", []string{"https://staging.sensibility.money/mcp"}, granted, false},
		{"named for a grant with none", []string{"https://sensibility.money/mcp"}, none, false},
		{"two values", []string{"https://sensibility.money/mcp", "https://sensibility.money/mcp"}, granted, false},
		{"malformed", []string{"https://sensibility.money/mcp#x"}, granted, false},
	}
	for _, c := range cases {
		if got := checkTokenRequestResource(c.values, c.granted); (got == "") != c.wantOK {
			t.Errorf("%s: checkTokenRequestResource = %q, want ok %v", c.name, got, c.wantOK)
		}
	}
}

func TestGrantedResource(t *testing.T) {
	s := &Server{config: &config.Config{JWTIssuer: "https://identity.example"}}
	def := sql.NullString{String: "ethanswan:fitness", Valid: true}
	if got := s.grantedResource(sql.NullString{String: "https://identity.example", Valid: true}, def); got.Valid {
		t.Errorf("a stored issuer means no resource, got %v", got)
	}
	if got := s.grantedResource(sql.NullString{String: "https://a.example", Valid: true}, def); got.String != "https://a.example" {
		t.Errorf("a stored resource is kept, got %v", got)
	}
	if got := s.grantedResource(sql.NullString{}, def); got != def {
		t.Errorf("a NULL (previous release) falls back to the legacy value, got %v", got)
	}
}

// TestCheckCodeIssuanceRefusesTargetBeforeTheSession: a malformed resource
// parameter needs no lookup and no session to be refused, so it is answered
// with invalid_target at once (the hermetic server has no database).
func TestCheckCodeIssuanceRefusesTargetBeforeTheSession(t *testing.T) {
	srv := newHermeticTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize", nil)
	_, denial := srv.checkCodeIssuance(req, testOAuthClient(), authorizeParams{
		ResponseType: "code", CodeChallenge: "challenge", CodeChallengeMethod: "S256", Scope: []string{"openid"},
		Resource: []string{"https://a.example", "https://b.example"},
	})
	if denial == nil || denial.Kind != denialInvalidParams || denial.OAuthError.Code != "invalid_target" {
		t.Fatalf("denial = %+v, want invalid_target", denial)
	}
}

// TestCheckCodeIssuanceRefusesResourceScopeWithoutResource: with no resource
// and no default, a non-identity scope is invalid_scope, again before any
// lookup or session.
func TestCheckCodeIssuanceRefusesResourceScopeWithoutResource(t *testing.T) {
	srv := newHermeticTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize", nil)
	client := db.OauthClient{AllowedScopes: []string{"openid", "sensibility:read"}, Kind: "registered"}
	_, denial := srv.checkCodeIssuance(req, client, authorizeParams{
		ResponseType: "code", CodeChallenge: "challenge", CodeChallengeMethod: "S256",
		Scope: []string{"openid", "sensibility:read"},
	})
	if denial == nil || denial.Kind != denialInvalidParams || denial.OAuthError.Code != "invalid_scope" {
		t.Fatalf("denial = %+v, want invalid_scope", denial)
	}
	if !strings.Contains(denial.OAuthError.Description, "sensibility:read") {
		t.Errorf("description %q should name the scope", denial.OAuthError.Description)
	}
}

// TestCheckCodeIssuanceResourceLookupFailureIsAServerError: when the
// registry cannot be read, the request is denied as a server error, never
// waved through and never blamed on the client.
func TestCheckCodeIssuanceResourceLookupFailureIsAServerError(t *testing.T) {
	srv := newHermeticTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize", nil)
	client := db.OauthClient{AllowedScopes: []string{"openid"}, Kind: "registered",
		DefaultResource: sql.NullString{String: "https://api.example", Valid: true}}
	_, denial := srv.checkCodeIssuance(req, client, authorizeParams{
		ResponseType: "code", CodeChallenge: "challenge", CodeChallengeMethod: "S256", Scope: []string{"openid"},
	})
	if denial == nil || denial.Kind != denialResourceLookupFailed {
		t.Fatalf("denial = %+v, want denialResourceLookupFailed", denial)
	}
}
