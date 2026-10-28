package httpserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/eswan18/identity/pkg/cimd"
	"github.com/eswan18/identity/pkg/config"
	"github.com/eswan18/identity/pkg/db"
	"github.com/eswan18/identity/pkg/email"
	"github.com/eswan18/identity/pkg/storage"
)

// These run against newHermeticTestServer, whose database is unreachable: a
// path that reached the database would fail with a connection error rather
// than errUnknownClient, so each test also proves the refusal came first.

const claudeCodeClientID = "https://claude.ai/oauth/claude-code-client-metadata"

func TestLookupClient_CIMDDisabledIsUnknownWithoutFetchOrQuery(t *testing.T) {
	srv := newHermeticTestServer(t)
	if srv.cimdEnabled() {
		t.Fatal("an empty CIMD_ALLOWED_HOSTS must leave CIMD disabled")
	}
	_, err := srv.lookupClient(t.Context(), claudeCodeClientID)
	if !errors.Is(err, errUnknownClient) {
		t.Fatalf("lookupClient = %v, want errUnknownClient", err)
	}
}

func TestLookupClient_HostNotAllowedIsUnknownWithoutFetch(t *testing.T) {
	srv := newHermeticTestServer(t)
	fake := newFakeClientMetadata("example.com")
	srv.clientMetadata = fake

	_, err := srv.lookupClient(t.Context(), claudeCodeClientID)
	if !errors.Is(err, errUnknownClient) || !errors.Is(err, cimd.ErrHostNotAllowed) {
		t.Fatalf("lookupClient = %v, want errUnknownClient and ErrHostNotAllowed", err)
	}
	if n := fake.fetchCount(claudeCodeClientID); n != 0 {
		t.Errorf("a host off the allow-list was fetched %d times", n)
	}
}

func TestLookupClient_ResolveErrorsAreUnknownClient(t *testing.T) {
	for name, resolveErr := range map[string]error{
		"fetch":            fmt.Errorf("%w: status 403", cimd.ErrFetch),
		"invalid document": fmt.Errorf("%w: client_id mismatch", cimd.ErrInvalidDocument),
	} {
		t.Run(name, func(t *testing.T) {
			srv := newHermeticTestServer(t)
			fake := newFakeClientMetadata("claude.ai")
			fake.fail(claudeCodeClientID, resolveErr)
			srv.clientMetadata = fake

			_, err := srv.lookupClient(t.Context(), claudeCodeClientID)
			if !errors.Is(err, errUnknownClient) || !errors.Is(err, resolveErr) {
				t.Fatalf("lookupClient = %v, want errUnknownClient wrapping %v", err, resolveErr)
			}
			if n := fake.fetchCount(claudeCodeClientID); n != 1 {
				t.Errorf("fetches = %d, want 1", n)
			}
		})
	}
}

// A document that cannot be resolved leaves the redirect_uri unverified, so
// /oauth/authorize answers with an error page and never redirects.
func TestAuthorize_CIMDResolveErrorIsAnErrorPage(t *testing.T) {
	srv := newHermeticTestServer(t)
	fake := newFakeClientMetadata("claude.ai")
	fake.fail(claudeCodeClientID, fmt.Errorf("%w: status 503", cimd.ErrFetch))
	srv.clientMetadata = fake

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {claudeCodeClientID},
		"redirect_uri":          {"http://localhost:51234/callback"},
		"scope":                 {"openid"},
		"state":                 {"st"},
		"code_challenge":        {strings.Repeat("a", 43)},
		"code_challenge_method": {"S256"},
	}
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("redirected to %q; an unverified redirect_uri must never be redirected to", loc)
	}
}

// At the token endpoint the same failure is invalid_client.
func TestToken_CIMDResolveErrorIsInvalidClient(t *testing.T) {
	srv := newHermeticTestServer(t)
	fake := newFakeClientMetadata("claude.ai")
	fake.fail(claudeCodeClientID, fmt.Errorf("%w: bad redirect_uris", cimd.ErrInvalidDocument))
	srv.clientMetadata = fake

	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x"}, "client_id": {claudeCodeClientID}}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "invalid_client" {
		t.Errorf("error = %q, want invalid_client", body["error"])
	}
}

// Introspection and revocation require a confidential client, which a
// metadata-document client never is; it is refused without a fetch.
func TestAuthenticateConfidentialClient_RefusesCIMDWithoutFetch(t *testing.T) {
	srv := newHermeticTestServer(t)
	fake := newFakeClientMetadata("claude.ai")
	fake.serve(claudeCodeClientID, "Claude Code", "http://localhost/callback")
	srv.clientMetadata = fake

	form := url.Values{"token": {"x"}, "client_id": {claudeCodeClientID}}
	req := httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()
	if _, err := srv.authenticateConfidentialClient(req); !errors.Is(err, ErrConfidentialClientRequired) {
		t.Errorf("authenticateConfidentialClient = %v, want ErrConfidentialClientRequired", err)
	}
	if n := fake.fetchCount(claudeCodeClientID); n != 0 {
		t.Errorf("fetches = %d, want 0", n)
	}
}

// The metadata endpoint advertises CIMD exactly when CIMD_ALLOWED_HOSTS names
// a host.
func TestMetadataEndpoint_CIMDFlagFollowsConfig(t *testing.T) {
	for _, hosts := range [][]string{nil, {"claude.ai"}} {
		srv := New(&config.Config{
			JWTPrivateKey:    testJWTECPrivateKey,
			JWTIssuer:        "https://identity.example.com",
			CIMDAllowedHosts: hosts,
		}, newHermeticTestServer(t).datastore, email.NewLogSender(), storage.NewLogStorage())
		t.Cleanup(func() { srv.Close() })

		rec := httptest.NewRecorder()
		srv.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))
		var doc map[string]any
		if err := json.NewDecoder(rec.Body).Decode(&doc); err != nil {
			t.Fatal(err)
		}
		_, present := doc["client_id_metadata_document_supported"]
		if want := len(hosts) > 0; present != want {
			t.Errorf("hosts %v: client_id_metadata_document_supported present = %v, want %v", hosts, present, want)
		}
	}
}

// A metadata-document client has no registered allowed_scopes, so
// validateAuthorizeParams leaves its scopes to checkCodeIssuance (computed
// from the resource), but every other rule, admin scopes included, holds.
func TestValidateAuthorizeParams_CIMDScopesAreComputedLater(t *testing.T) {
	client := db.OauthClient{ClientID: claudeCodeClientID, Kind: clientKindCIMD}
	if err := validateAuthorizeParams(client, "code", "challenge", "S256", []string{"openid", "sensibility:read"}); err != nil {
		t.Errorf("validateAuthorizeParams = %+v, want nil", err)
	}
	if err := validateAuthorizeParams(client, "code", "challenge", "S256", []string{"admin:users:read"}); err == nil || err.Code != "invalid_scope" {
		t.Errorf("admin scope: %+v, want invalid_scope", err)
	}
	if err := validateAuthorizeParams(client, "code", "", "", []string{"openid"}); err == nil || err.Code != "invalid_request" {
		t.Errorf("no PKCE: %+v, want invalid_request", err)
	}
}

func TestCIMDAllowedScopes(t *testing.T) {
	if got := cimdAllowedScopes(nil); !slices.Equal(got, []string{"openid", "profile", "email", "offline_access"}) {
		t.Errorf("no resource: %v, want identity's user scopes", got)
	}
	got := cimdAllowedScopes(&resolvedResource{URI: "https://sensibility.money/mcp", Scopes: map[string]string{
		"sensibility:read": "Read", "sensibility:write": "Write",
	}})
	for _, want := range []string{"openid", "offline_access", "sensibility:read", "sensibility:write"} {
		if !slices.Contains(got, want) {
			t.Errorf("with a resource: %v lacks %q", got, want)
		}
	}
	if slices.ContainsFunc(got, func(sc string) bool { return strings.HasPrefix(sc, "admin:") }) {
		t.Errorf("admin scopes are never computed in: %v", got)
	}
}

func TestSameStringSet(t *testing.T) {
	for _, tc := range []struct {
		a, b []string
		want bool
	}{
		{nil, nil, true},
		{[]string{"a", "b"}, []string{"b", "a"}, true},
		{[]string{"a", "a", "b"}, []string{"b", "a"}, true},
		{[]string{"a"}, []string{"a", "b"}, false},
		{[]string{"a"}, []string{"b"}, false},
	} {
		if got := sameStringSet(tc.a, tc.b); got != tc.want {
			t.Errorf("sameStringSet(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}
