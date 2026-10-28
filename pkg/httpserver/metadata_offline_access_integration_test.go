//go:build integration

package httpserver

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/eswan18/identity/pkg/db"
)

// Both well-known paths answer the live server with one document whose issuer
// is byte-identical to the iss identity signs into its tokens.
func (s *OAuthFlowSuite) TestAuthorizationServerMetadataBothPaths() {
	fetch := func(path string) []byte {
		resp, err := s.httpClient.Get("http://localhost:8080" + path)
		s.Require().NoError(err)
		defer resp.Body.Close()
		s.Require().Equal(http.StatusOK, resp.StatusCode, path)
		s.Equal("application/json", resp.Header.Get("Content-Type"), path)
		body, err := io.ReadAll(resp.Body)
		s.Require().NoError(err)
		return body
	}
	oidc := fetch("/.well-known/openid-configuration")
	rfc8414 := fetch("/.well-known/oauth-authorization-server")
	s.Equal(string(oidc), string(rfc8414), "both paths must serve the same document")

	var doc map[string]any
	s.Require().NoError(json.Unmarshal(rfc8414, &doc))
	s.Equal("http://localhost:8080", doc["issuer"])
	s.Contains(doc["token_endpoint_auth_methods_supported"], "none")
	s.Contains(doc["scopes_supported"], "offline_access")
	s.Contains(doc["code_challenge_methods_supported"], "S256")
	s.Equal(true, doc["authorization_response_iss_parameter_supported"])
	// The suite allows claude.ai documents (SetupSuite), so CIMD is
	// advertised; with no allowed host it is omitted (metadata_test.go).
	s.Equal(true, doc["client_id_metadata_document_supported"])
	for key, v := range doc {
		if arr, ok := v.([]any); ok {
			s.NotEmpty(arr, "%s must be omitted rather than empty", key)
		}
	}

	// The issuer in the document is the iss in an ID token, byte for byte.
	result := s.mustCompleteOAuthFlow(db.CreateOAuthClientParams{
		ClientID:        s.mustGenerateRandomString(8),
		Name:            s.mustGenerateRandomString(8),
		RedirectUris:    []string{"http://localhost:8080/callback"},
		AllowedScopes:   []string{"openid"},
		DefaultResource: testResource("http://localhost:8080"),
	}, "openid")
	parts := strings.Split(result.TokenResponse.IDToken, ".")
	s.Require().Len(parts, 3)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	s.Require().NoError(err)
	var claims map[string]any
	s.Require().NoError(json.Unmarshal(payload, &claims))
	s.Equal(doc["issuer"], claims["iss"])
}

// A public client may ask for offline_access without having it registered,
// and still gets its refresh token (as every code exchange does).
func (s *OAuthFlowSuite) TestOfflineAccessWithoutRegistration() {
	result := s.mustCompleteOAuthFlow(db.CreateOAuthClientParams{
		ClientID:        s.mustGenerateRandomString(8),
		ClientSecret:    sql.NullString{},
		Name:            s.mustGenerateRandomString(8),
		RedirectUris:    []string{"http://localhost:8080/callback"},
		AllowedScopes:   []string{"openid"},
		IsConfidential:  false,
		DefaultResource: testResource("http://localhost:8080"),
	}, "openid offline_access")

	s.NotEmpty(result.TokenResponse.AccessToken)
	s.NotEmpty(result.TokenResponse.RefreshToken)
	s.ElementsMatch([]string{"openid", "offline_access"}, strings.Fields(result.TokenResponse.Scope))

	// The refresh token works and carries the scope forward.
	resp, err := s.httpClient.PostForm("http://localhost:8080/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {result.TokenResponse.RefreshToken},
		"client_id":     {result.Client.ClientID},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)
	var refreshed TokenResponse
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&refreshed))
	s.NotEmpty(refreshed.RefreshToken)
	s.ElementsMatch([]string{"openid", "offline_access"}, strings.Fields(refreshed.Scope))
}

// The consent screen explains offline_access in plain words.
func (s *OAuthFlowSuite) TestOfflineAccessConsentDescription() {
	httpClient, client := s.mustLoginAndGetAuthorizeClient(db.CreateOAuthClientParams{
		ClientID:        s.mustGenerateRandomString(8),
		Name:            s.mustGenerateRandomString(8),
		RedirectUris:    []string{"http://localhost:8080/callback"},
		AllowedScopes:   []string{"openid"},
		DefaultResource: testResource("http://localhost:8080"),
	})
	scv := s.mustCreateStateAndCodeVerifier()
	authorize := "http://localhost:8080/oauth/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {client.ClientID},
		"redirect_uri":          {"http://localhost:8080/callback"},
		"scope":                 {"openid offline_access"},
		"state":                 {scv.State},
		"code_challenge":        {scv.CodeChallenge},
		"code_challenge_method": {"S256"},
	}.Encode()
	resp, err := httpClient.Get(authorize)
	s.Require().NoError(err)
	resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	consent := resp.Header.Get("Location")
	s.Require().True(strings.HasPrefix(consent, "/oauth/consent?"), "authorize should send the user to consent, got %q", consent)

	resp, err = httpClient.Get("http://localhost:8080" + consent)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	s.Contains(string(body), "Stay signed in")
}

// offline_access never rides client_credentials: refused when asked for, and
// left out of the default scope even when a registration lists it.
func (s *OAuthFlowSuite) TestOfflineAccessRefusedOnClientCredentials() {
	secret := s.mustGenerateRandomString(32)
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:        s.mustGenerateRandomString(8),
		ClientSecret:    sql.NullString{String: secret, Valid: true},
		Name:            s.mustGenerateRandomString(8),
		RedirectUris:    []string{"http://localhost:8080/callback"},
		AllowedScopes:   []string{"admin:users:read", "offline_access"},
		IsConfidential:  true,
		DefaultResource: testResource("http://localhost:8080"),
	})

	post := func(scope string) (int, map[string]any) {
		form := url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {client.ClientID},
			"client_secret": {secret},
		}
		if scope != "" {
			form.Set("scope", scope)
		}
		resp, err := s.httpClient.PostForm("http://localhost:8080/oauth/token", form)
		s.Require().NoError(err)
		defer resp.Body.Close()
		var body map[string]any
		s.Require().NoError(json.NewDecoder(resp.Body).Decode(&body))
		return resp.StatusCode, body
	}

	for _, scope := range []string{"offline_access", "admin:users:read offline_access"} {
		code, body := post(scope)
		s.Equal(http.StatusBadRequest, code, scope)
		s.Equal("invalid_scope", body["error"], scope)
	}

	code, body := post("")
	s.Require().Equal(http.StatusOK, code)
	s.Equal("admin:users:read", body["scope"], "the default scope must leave offline_access out")
	s.NotContains(body, "refresh_token")
}

// The live server gives the protocol endpoints more than the general 20/min
// from one IP, and keeps the login form at 20.
func (s *OAuthFlowSuite) TestProtocolEndpointRateLimits() {
	get := func(path string) int {
		req, err := http.NewRequest(http.MethodGet, "http://localhost:8080"+path, nil)
		s.Require().NoError(err)
		req.Header.Set("CF-Connecting-IP", "160.79.104.7")
		resp, err := s.httpClient.Do(req)
		s.Require().NoError(err)
		resp.Body.Close()
		return resp.StatusCode
	}
	for i := range 3 * generalRateLimitPerMinute {
		for _, path := range []string{
			"/.well-known/openid-configuration",
			"/.well-known/oauth-authorization-server",
			"/.well-known/jwks.json",
		} {
			s.Require().Equal(http.StatusOK, get(path), "request %d to %s", i+1, path)
		}
	}
	for i := range generalRateLimitPerMinute {
		s.Require().NotEqual(http.StatusTooManyRequests, get("/oauth/login"), "login request %d", i+1)
	}
	s.Equal(http.StatusTooManyRequests, get("/oauth/login"), "login keeps the general budget")
}
