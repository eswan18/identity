//go:build integration

package httpserver

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/eswan18/identity/pkg/db"
)

// Tests for the resource parameter end to end (spec
// docs/superpowers/specs/2026-10-27-resource-indicators-and-mcp-clients-design.md,
// sections 2, 3 and 8): authorize, consent, the code exchange, refresh and
// client_credentials.

const testBaseURL = "http://localhost:8080"

// randomResourceURI is a fresh canonical https resource URI, so tests sharing
// the suite's database never collide.
func (s *OAuthFlowSuite) randomResourceURI() string {
	return "https://" + strings.ToLower(s.mustGenerateAlphanumericString(12)) + ".example.com/mcp"
}

// mustRegisterResource registers a resource with the given scopes.
func (s *OAuthFlowSuite) mustRegisterResource(uri, name string, scopes map[string]string) db.OauthResource {
	s.T().Helper()
	if scopes == nil {
		scopes = map[string]string{}
	}
	raw, err := json.Marshal(scopes)
	s.Require().NoError(err)
	resource, err := s.datastore.Q.CreateOAuthResource(s.T().Context(), db.CreateOAuthResourceParams{
		Uri:    uri,
		Name:   name,
		Scopes: raw,
	})
	s.Require().NoError(err)
	return resource
}

// mustAllowResources puts resources on a client's allow-list.
func (s *OAuthFlowSuite) mustAllowResources(client db.OauthClient, resources ...db.OauthResource) {
	s.T().Helper()
	for _, r := range resources {
		s.Require().NoError(s.datastore.Q.AddClientResource(s.T().Context(), db.AddClientResourceParams{
			ClientID: client.ID, ResourceID: r.ID,
		}))
	}
}

// resourceClientParams is a public client registered at the suite's callback,
// allowed the given scopes, with no default resource.
func (s *OAuthFlowSuite) resourceClientParams(scopes ...string) db.CreateOAuthClientParams {
	return db.CreateOAuthClientParams{
		ClientID:      s.mustGenerateRandomString(8),
		Name:          "Resource Client " + s.mustGenerateAlphanumericString(6),
		RedirectUris:  []string{testBaseURL + "/callback"},
		AllowedScopes: scopes,
	}
}

// authorizeQueryWithResource is an authorize request for client with the
// given scope and resource parameter values (none: no resource parameter).
func authorizeQueryWithResource(client db.OauthClient, scope string, scv StateAndCodeVerifier, resources ...string) string {
	var extra url.Values
	if len(resources) > 0 {
		extra = url.Values{"resource": resources}
	}
	return authorizeQueryFor(client.ClientID, client.RedirectUris[0], scope, scv, extra)
}

// get issues a GET from a signed-in browser without following redirects.
func (s *OAuthFlowSuite) get(httpClient *http.Client, rawURL string) *http.Response {
	s.T().Helper()
	resp, err := httpClient.Get(rawURL)
	s.Require().NoError(err)
	return resp
}

// requireClientError asserts resp redirects to the client's callback with the
// given OAuth error, carrying iss.
func (s *OAuthFlowSuite) requireClientError(resp *http.Response, wantError string) {
	s.T().Helper()
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	location, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Require().Equal(testBaseURL+"/callback", location.Scheme+"://"+location.Host+location.Path,
		"expected a redirect to the client, got %s", resp.Header.Get("Location"))
	s.Equal(wantError, location.Query().Get("error"), "error_description: %s", location.Query().Get("error_description"))
	s.Equal(testBaseURL, location.Query().Get("iss"))
}

// requireConsentRedirect asserts resp redirects to the consent page and returns its URL.
func (s *OAuthFlowSuite) requireConsentRedirect(resp *http.Response) string {
	s.T().Helper()
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	location := resp.Header.Get("Location")
	s.Require().True(strings.HasPrefix(location, "/oauth/consent?"), "expected the consent page, got %s", location)
	return testBaseURL + location
}

// requireCode asserts resp redirects to the client with a code and returns it.
func (s *OAuthFlowSuite) requireCode(resp *http.Response) string {
	s.T().Helper()
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	location, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	code := location.Query().Get("code")
	s.Require().NotEmpty(code, "expected a code, got %s", resp.Header.Get("Location"))
	return code
}

// mustConsentPage fetches the consent page and returns its HTML.
func (s *OAuthFlowSuite) mustConsentPage(httpClient *http.Client, consentURL string) string {
	s.T().Helper()
	resp := s.get(httpClient, consentURL)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, resp.StatusCode, "consent page: %s", body)
	return string(body)
}

// mustApprove approves the consent page at consentURL and returns the code.
func (s *OAuthFlowSuite) mustApprove(httpClient *http.Client, consentURL string) string {
	s.T().Helper()
	u, err := url.Parse(consentURL)
	s.Require().NoError(err)
	resp, err := csrfPostFormLogin(s.T(), httpClient, testBaseURL+"/oauth/consent", url.Values{
		"decision":        {"allow"},
		"authorize_query": {u.Query().Get("authorize_query")},
	})
	s.Require().NoError(err)
	return s.requireCode(resp)
}

// postTokenForm posts a token request and returns the status and decoded body.
func (s *OAuthFlowSuite) postTokenForm(form url.Values) (int, map[string]any) {
	s.T().Helper()
	resp, err := s.httpClient.PostForm(testBaseURL+"/oauth/token", form)
	s.Require().NoError(err)
	defer resp.Body.Close()
	var body map[string]any
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&body))
	return resp.StatusCode, body
}

// exchangeForm is the code-exchange request for code, plus any extra fields.
func exchangeForm(client db.OauthClient, code string, scv StateAndCodeVerifier, extra url.Values) url.Values {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {client.RedirectUris[0]},
		"client_id":     {client.ClientID},
		"code_verifier": {scv.CodeVerifier},
	}
	for k, v := range extra {
		form[k] = v
	}
	return form
}

// mustCodeFor runs authorize -> consent -> approve for a signed-in browser
// and returns the code.
func (s *OAuthFlowSuite) mustCodeFor(httpClient *http.Client, query string) string {
	s.T().Helper()
	consentURL := s.requireConsentRedirect(s.get(httpClient, testBaseURL+"/oauth/authorize?"+query))
	return s.mustApprove(httpClient, consentURL)
}

// TestResourceParameterHappyPath: a client asks for a resource on its
// allow-list, with that resource's scope. The consent screen names the
// resource and describes its scope from the registry; the token's aud is the
// resource, through the exchange and a refresh, and a resource parameter that
// repeats the granted one is accepted at both.
func (s *OAuthFlowSuite) TestResourceParameterHappyPath() {
	resourceURI := s.randomResourceURI()
	resource := s.mustRegisterResource(resourceURI, "Sensibility Test", map[string]string{
		"sens:read": "Read your accounts and balances",
	})
	httpClient, client := s.mustLoginAndGetAuthorizeClient(s.resourceClientParams("openid", "sens:read"))
	s.mustAllowResources(client, resource)
	scv := s.mustCreateStateAndCodeVerifier()

	query := authorizeQueryWithResource(client, "sens:read offline_access", scv, resourceURI)
	consentURL := s.requireConsentRedirect(s.get(httpClient, testBaseURL+"/oauth/authorize?"+query))
	page := s.mustConsentPage(httpClient, consentURL)
	s.Contains(page, "Sensibility Test")
	s.Contains(page, "("+strings.TrimSuffix(strings.TrimPrefix(resourceURI, "https://"), "/mcp")+")", "the resource's host")
	s.Contains(page, "Read your accounts and balances", "the scope's description from the registry")
	s.Contains(page, "Stay signed in", "identity's own scopes keep their descriptions")
	s.NotContains(page, "sens:read", "a raw scope string is never shown")
	s.Contains(page, "<strong>localhost:8080</strong>", "where the answer goes")

	code := s.mustApprove(httpClient, consentURL)
	status, body := s.postTokenForm(exchangeForm(client, code, scv, url.Values{"resource": {resourceURI}}))
	s.Require().Equal(http.StatusOK, status, "%v", body)
	access := body["access_token"].(string)
	s.Equal(`["`+resourceURI+`"]`, s.accessTokenRawAud(access))
	s.Equal("sens:read offline_access", body["scope"])
	refresh := body["refresh_token"].(string)
	s.Equal(testResource(resourceURI), s.tokenRowResource(s.datastore, refresh))

	status, body = s.postTokenForm(url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		"client_id":     {client.ClientID},
		"resource":      {resourceURI},
	})
	s.Require().Equal(http.StatusOK, status, "%v", body)
	s.Equal(`["`+resourceURI+`"]`, s.accessTokenRawAud(body["access_token"].(string)))
}

// TestResourceParameterCanonicalized: the resource parameter is
// canonicalized before lookup, so the spec's example spelling finds the
// registered resource, and the token's aud is the canonical URI.
func (s *OAuthFlowSuite) TestResourceParameterCanonicalized() {
	const canonical = "https://sensibility.money/mcp"
	_, err := s.datastore.DB.ExecContext(s.T().Context(),
		`INSERT INTO oauth_resources (uri, name, scopes) VALUES ($1, 'Sensibility', '{"sensibility:read": "Read your data"}')
		 ON CONFLICT (uri) DO NOTHING`, canonical)
	s.Require().NoError(err)
	resource, err := s.datastore.Q.GetOAuthResourceByURI(s.T().Context(), canonical)
	s.Require().NoError(err)

	httpClient, client := s.mustLoginAndGetAuthorizeClient(s.resourceClientParams("sensibility:read"))
	s.mustAllowResources(client, resource)
	scv := s.mustCreateStateAndCodeVerifier()

	code := s.mustCodeFor(httpClient, authorizeQueryWithResource(client, "sensibility:read", scv, "HTTPS://Sensibility.money/mcp/"))
	status, body := s.postTokenForm(exchangeForm(client, code, scv, url.Values{"resource": {"https://SENSIBILITY.money:443/mcp"}}))
	s.Require().Equal(http.StatusOK, status, "%v", body)
	s.Equal(`["`+canonical+`"]`, s.accessTokenRawAud(body["access_token"].(string)))
}

// TestResourceParameterInvalidTarget: every way a resource parameter on
// /oauth/authorize can be unusable is answered with invalid_target,
// redirected to the client with iss -- before any sign-in is asked for.
func (s *OAuthFlowSuite) TestResourceParameterInvalidTarget() {
	allowed := s.mustRegisterResource(s.randomResourceURI(), "Allowed", map[string]string{"a:read": "Read A"})
	notAllowed := s.mustRegisterResource(s.randomResourceURI(), "Not Allowed", map[string]string{"a:read": "Read A"})
	httpClient, client := s.mustLoginAndGetAuthorizeClient(s.resourceClientParams("openid", "a:read"))
	s.mustAllowResources(client, allowed)
	scv := s.mustCreateStateAndCodeVerifier()

	cases := map[string][]string{
		"unknown resource":         {"https://nobody-registered-this.example.com/mcp"},
		"fragment":                 {allowed.Uri + "#frag"},
		"relative":                 {"/mcp"},
		"empty":                    {""},
		"two values":               {allowed.Uri, notAllowed.Uri},
		"two values, the same one": {allowed.Uri, allowed.Uri},
		"not allowed for client":   {notAllowed.Uri},
	}
	for name, resources := range cases {
		s.Run(name, func() {
			query := authorizeQueryWithResource(client, "openid", scv, resources...)
			s.requireClientError(s.get(httpClient, testBaseURL+"/oauth/authorize?"+query), "invalid_target")

			// Signed out, the answer is the same: there is no point asking
			// someone to sign in for a request that cannot succeed.
			s.requireClientError(s.get(s.httpClient, testBaseURL+"/oauth/authorize?"+query), "invalid_target")
		})
	}

	// The consent POST re-checks the carried request the same way.
	resp, err := csrfPostFormLogin(s.T(), httpClient, testBaseURL+"/oauth/consent", url.Values{
		"decision":        {"allow"},
		"authorize_query": {authorizeQueryWithResource(client, "openid", scv, notAllowed.Uri)},
	})
	s.Require().NoError(err)
	s.requireClientError(resp, "invalid_target")
}

// TestResourceParameterInvalidScope: each requested scope must be identity's
// own or defined by the one resource the request resolved to, and (for a
// registered client) in its allowed_scopes.
func (s *OAuthFlowSuite) TestResourceParameterInvalidScope() {
	a := s.mustRegisterResource(s.randomResourceURI(), "A", map[string]string{"a:read": "Read A", "a:write": "Change A"})
	b := s.mustRegisterResource(s.randomResourceURI(), "B", map[string]string{"b:read": "Read B"})
	httpClient, client := s.mustLoginAndGetAuthorizeClient(s.resourceClientParams("openid", "a:read", "b:read"))
	s.mustAllowResources(client, a, b)
	scv := s.mustCreateStateAndCodeVerifier()

	cases := map[string]string{
		// No resource named and the client has no default: only identity's
		// scopes can be granted.
		"resource scope without a resource": authorizeQueryWithResource(client, "openid a:read", scv),
		// b:read is allowed for the client and defined by B, but the request
		// is for A.
		"scope of another resource": authorizeQueryWithResource(client, "a:read b:read", scv, a.Uri),
		// a:write is defined by A, but not in the client's allowed_scopes.
		"outside allowed_scopes": authorizeQueryWithResource(client, "a:read a:write", scv, a.Uri),
		// Defined by nobody.
		"unknown scope": authorizeQueryWithResource(client, "a:read a:delete", scv, a.Uri),
	}
	for name, query := range cases {
		s.Run(name, func() {
			s.requireClientError(s.get(httpClient, testBaseURL+"/oauth/authorize?"+query), "invalid_scope")
		})
	}

	// The consent page refuses the same request rather than rendering the
	// unknown scope raw.
	consentURL := testBaseURL + "/oauth/consent?" + url.Values{
		"authorize_query": {authorizeQueryWithResource(client, "a:read a:delete", scv, a.Uri)},
	}.Encode()
	s.requireClientError(s.get(httpClient, consentURL), "invalid_scope")
}

// TestResourceParameterAtCodeExchange: the code's resource is fixed at
// authorize time. A resource parameter at the exchange may only repeat it; a
// different one is invalid_target and leaves the code redeemable. A code for
// no resource takes no resource parameter.
func (s *OAuthFlowSuite) TestResourceParameterAtCodeExchange() {
	a := s.mustRegisterResource(s.randomResourceURI(), "A", map[string]string{"a:read": "Read A"})
	b := s.mustRegisterResource(s.randomResourceURI(), "B", map[string]string{"b:read": "Read B"})
	httpClient, client := s.mustLoginAndGetAuthorizeClient(s.resourceClientParams("openid", "a:read", "b:read"))
	s.mustAllowResources(client, a, b)

	scv := s.mustCreateStateAndCodeVerifier()
	code := s.mustCodeFor(httpClient, authorizeQueryWithResource(client, "a:read", scv, a.Uri))
	for name, extra := range map[string]url.Values{
		"another resource": {"resource": {b.Uri}},
		"two values":       {"resource": {a.Uri, a.Uri}},
		"malformed":        {"resource": {a.Uri + "#x"}},
	} {
		status, body := s.postTokenForm(exchangeForm(client, code, scv, extra))
		s.Equal(http.StatusBadRequest, status, name)
		s.Equal("invalid_target", body["error"], name)
	}
	status, body := s.postTokenForm(exchangeForm(client, code, scv, nil))
	s.Require().Equal(http.StatusOK, status, "the code survives a refused exchange: %v", body)
	s.Equal(`["`+a.Uri+`"]`, s.accessTokenRawAud(body["access_token"].(string)))

	// A code for no resource (identity scopes only, no default).
	scv = s.mustCreateStateAndCodeVerifier()
	code = s.mustCodeFor(httpClient, authorizeQueryWithResource(client, "openid", scv))
	status, body = s.postTokenForm(exchangeForm(client, code, scv, url.Values{"resource": {a.Uri}}))
	s.Equal(http.StatusBadRequest, status)
	s.Equal("invalid_target", body["error"])
	status, body = s.postTokenForm(exchangeForm(client, code, scv, nil))
	s.Require().Equal(http.StatusOK, status, "%v", body)
	s.Equal(`["`+testBaseURL+`"]`, s.accessTokenRawAud(body["access_token"].(string)))
}

// TestResourceParameterAtRefresh: a refresh keeps the stored resource; a
// resource parameter naming another one is invalid_target and does not spend
// the refresh token. A token for identity itself takes no resource parameter.
func (s *OAuthFlowSuite) TestResourceParameterAtRefresh() {
	a := s.mustRegisterResource(s.randomResourceURI(), "A", map[string]string{"a:read": "Read A"})
	b := s.mustRegisterResource(s.randomResourceURI(), "B", map[string]string{"b:read": "Read B"})
	httpClient, client := s.mustLoginAndGetAuthorizeClient(s.resourceClientParams("openid", "a:read", "b:read"))
	s.mustAllowResources(client, a, b)

	refreshWith := func(refreshToken string, resources ...string) (int, map[string]any) {
		form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}, "client_id": {client.ClientID}}
		if len(resources) > 0 {
			form["resource"] = resources
		}
		return s.postTokenForm(form)
	}

	scv := s.mustCreateStateAndCodeVerifier()
	code := s.mustCodeFor(httpClient, authorizeQueryWithResource(client, "a:read", scv, a.Uri))
	status, body := s.postTokenForm(exchangeForm(client, code, scv, nil))
	s.Require().Equal(http.StatusOK, status, "%v", body)
	refresh := body["refresh_token"].(string)

	status, body = refreshWith(refresh, b.Uri)
	s.Equal(http.StatusBadRequest, status)
	s.Equal("invalid_target", body["error"], "a refresh can never re-point a grant")
	status, body = refreshWith(refresh)
	s.Require().Equal(http.StatusOK, status, "the refused refresh did not spend the token: %v", body)
	s.Equal(`["`+a.Uri+`"]`, s.accessTokenRawAud(body["access_token"].(string)))

	// A token for identity itself: the stored issuer means no resource.
	scv = s.mustCreateStateAndCodeVerifier()
	code = s.mustCodeFor(httpClient, authorizeQueryWithResource(client, "openid", scv))
	status, body = s.postTokenForm(exchangeForm(client, code, scv, nil))
	s.Require().Equal(http.StatusOK, status, "%v", body)
	status, body = refreshWith(body["refresh_token"].(string), a.Uri)
	s.Equal(http.StatusBadRequest, status)
	s.Equal("invalid_target", body["error"], "a grant for identity itself cannot be widened to a resource")
}

// TestNoResourceParameterUnchanged is the compatibility guarantee: a client
// that sends no resource gets exactly the aud it got before -- its default
// resource -- through the exchange and refreshes. footstrike's URN-style
// default is the case that matters, and naming it explicitly works too.
func (s *OAuthFlowSuite) TestNoResourceParameterUnchanged() {
	const fitness = "ethanswan:fitness"
	params := s.resourceClientParams("openid", "profile", "email")
	params.DefaultResource = testResource(fitness)
	result := s.mustCompleteOAuthFlow(params)
	s.Equal(`["`+fitness+`"]`, s.accessTokenRawAud(result.TokenResponse.AccessToken))
	s.Equal(testResource(fitness), s.tokenRowResource(s.datastore, result.TokenResponse.RefreshToken))
	refreshed := s.mustRefreshAt(testBaseURL, result.Client.ClientID, result.TokenResponse.RefreshToken)
	s.Equal(`["`+fitness+`"]`, s.accessTokenRawAud(refreshed.AccessToken))

	// Naming the default is the same as naming nothing.
	httpClient, client := s.mustLoginAndGetAuthorizeClient(func() db.CreateOAuthClientParams {
		p := s.resourceClientParams("openid")
		p.DefaultResource = testResource(fitness)
		return p
	}())
	scv := s.mustCreateStateAndCodeVerifier()
	code := s.mustCodeFor(httpClient, authorizeQueryWithResource(client, "openid", scv, fitness))
	status, body := s.postTokenForm(exchangeForm(client, code, scv, url.Values{"resource": {fitness}}))
	s.Require().Equal(http.StatusOK, status, "%v", body)
	s.Equal(`["`+fitness+`"]`, s.accessTokenRawAud(body["access_token"].(string)))
}

// TestCodeFromPreviousReleaseGetsClientDefault: a code the previous release
// wrote has no resource; it minted for the client's default, so exchanging
// it under this release must too.
func (s *OAuthFlowSuite) TestCodeFromPreviousReleaseGetsClientDefault() {
	params := s.resourceClientParams("openid")
	params.DefaultResource = testResource("https://previous-release.example.com")
	httpClient, client := s.mustLoginAndGetAuthorizeClient(params)
	scv := s.mustCreateStateAndCodeVerifier()
	code := s.mustCodeFor(httpClient, authorizeQueryWithResource(client, "openid", scv))

	_, err := s.datastore.DB.ExecContext(s.T().Context(),
		`UPDATE oauth_authorization_codes SET resource = NULL WHERE code = $1`, code)
	s.Require().NoError(err)

	status, body := s.postTokenForm(exchangeForm(client, code, scv, nil))
	s.Require().Equal(http.StatusOK, status, "%v", body)
	s.Equal(`["https://previous-release.example.com"]`, s.accessTokenRawAud(body["access_token"].(string)))
}

// TestConsentRememberedPerResource: approving resource A for a client does
// not approve resource B for it. A again is not asked; B is.
func (s *OAuthFlowSuite) TestConsentRememberedPerResource() {
	a := s.mustRegisterResource(s.randomResourceURI(), "A", map[string]string{"x:read": "Read A"})
	b := s.mustRegisterResource(s.randomResourceURI(), "B", map[string]string{"x:read": "Read B"})
	httpClient, client := s.mustLoginAndGetAuthorizeClient(s.resourceClientParams("x:read"))
	s.mustAllowResources(client, a, b)
	scv := s.mustCreateStateAndCodeVerifier()

	s.mustCodeFor(httpClient, authorizeQueryWithResource(client, "x:read", scv, a.Uri))

	again := s.get(httpClient, testBaseURL+"/oauth/authorize?"+authorizeQueryWithResource(client, "x:read", scv, a.Uri))
	s.requireCode(again)

	other := s.get(httpClient, testBaseURL+"/oauth/authorize?"+authorizeQueryWithResource(client, "x:read", scv, b.Uri))
	consentURL := s.requireConsentRedirect(other)
	s.Contains(s.mustConsentPage(httpClient, consentURL), "Read B", "the page describes B's scope, not A's")
}

// TestConsentPageWarnsForLoopbackOnlyClient: a client whose only redirect
// URIs are loopback ones (Claude Code registers http://localhost/callback)
// gets the "runs on your computer" warning, and the page names the host the
// answer goes to, port included. A client with a web redirect gets neither
// the warning nor a loopback host.
func (s *OAuthFlowSuite) TestConsentPageWarnsForLoopbackOnlyClient() {
	const warning = "This app runs on your computer"

	params := s.resourceClientParams("openid")
	params.RedirectUris = []string{"http://localhost/callback"}
	httpClient, client := s.mustLoginAndGetAuthorizeClient(params)
	scv := s.mustCreateStateAndCodeVerifier()
	query := authorizeQueryFor(client.ClientID, "http://localhost:54321/callback", "openid", scv, nil)
	page := s.mustConsentPage(httpClient, testBaseURL+"/oauth/consent?"+url.Values{"authorize_query": {query}}.Encode())
	s.Contains(page, warning)
	s.Contains(page, "<strong>localhost:54321</strong>")

	webParams := s.resourceClientParams("openid")
	webParams.RedirectUris = []string{"https://app.example.com/callback", "http://localhost/callback"}
	webBrowser, webClient := s.mustLoginAndGetAuthorizeClient(webParams)
	query = authorizeQueryFor(webClient.ClientID, "https://app.example.com/callback", "openid", scv, nil)
	page = s.mustConsentPage(webBrowser, testBaseURL+"/oauth/consent?"+url.Values{"authorize_query": {query}}.Encode())
	s.NotContains(page, warning, "one non-loopback redirect URI is enough not to warn")
	s.Contains(page, "<strong>app.example.com</strong>")
}

// TestClientCredentialsResource: client_credentials honors the resource
// parameter the same way -- a resource on the allow-list, else the client's
// default, else identity itself -- and refuses one it may not have.
func (s *OAuthFlowSuite) TestClientCredentialsResource() {
	allowed := s.mustRegisterResource(s.randomResourceURI(), "Allowed", nil)
	other := s.mustRegisterResource(s.randomResourceURI(), "Other", nil)
	secret := s.mustGenerateRandomString(32)
	params := s.resourceClientParams("svc:read")
	params.ClientSecret = sql.NullString{String: secret, Valid: true}
	params.IsConfidential = true
	params.DefaultResource = testResource("https://svc-default.example.com")
	client := s.mustRegisterOAuthClient(params)
	s.mustAllowResources(client, allowed)

	form := func(resources ...string) url.Values {
		f := url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {client.ClientID},
			"client_secret": {secret},
			"scope":         {"svc:read"},
		}
		if len(resources) > 0 {
			f["resource"] = resources
		}
		return f
	}

	status, body := s.postTokenForm(form())
	s.Require().Equal(http.StatusOK, status, "%v", body)
	s.Equal(`["https://svc-default.example.com"]`, s.accessTokenRawAud(body["access_token"].(string)))

	status, body = s.postTokenForm(form(allowed.Uri))
	s.Require().Equal(http.StatusOK, status, "%v", body)
	s.Equal(`["`+allowed.Uri+`"]`, s.accessTokenRawAud(body["access_token"].(string)))

	for name, resources := range map[string][]string{
		"not allowed": {other.Uri},
		"unknown":     {"https://unknown.example.com"},
		"two values":  {allowed.Uri, other.Uri},
	} {
		status, body = s.postTokenForm(form(resources...))
		s.Equal(http.StatusBadRequest, status, name)
		s.Equal("invalid_target", body["error"], name)
	}
}
