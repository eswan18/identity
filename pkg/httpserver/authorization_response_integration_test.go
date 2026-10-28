//go:build integration

package httpserver

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"

	"github.com/eswan18/identity/pkg/db"
)

// testIssuer is the suite server's JWT_ISSUER (see SetupSuite).
const testIssuer = "http://localhost:8080"

// TestEveryAuthorizationResponseCarriesIss walks every way identity redirects
// the user agent back to a client -- a code or an error, from authorize,
// consent and the login page -- and checks each carries iss equal to the
// issuer (RFC 9207), with and without state. The discovery document advertises
// authorization_response_iss_parameter_supported, and a client that has seen
// that rejects any response without iss, so one path that skips it breaks that
// client.
//
// server_error is not here: its paths (a user lookup or a database write
// failing mid-request) cannot be provoked against a healthy database. They
// share the redirectError closure, and so respondWithError, with the paths
// below; TestDenyCodeIssuanceRoutesEachKind pins that a lookup failure goes to
// that closure.
func (s *OAuthFlowSuite) TestEveryAuthorizationResponseCarriesIss() {
	const callback = "http://localhost:8080/callback"

	authorize := func(c *http.Client, q url.Values) *http.Response {
		resp, err := c.Get("http://localhost:8080/oauth/authorize?" + q.Encode())
		s.Require().NoError(err)
		return resp
	}
	consent := func(c *http.Client, decision string, q url.Values) *http.Response {
		resp, err := csrfPostFormLogin(s.T(), c, "http://localhost:8080/oauth/consent", url.Values{
			"decision":        {decision},
			"authorize_query": {q.Encode()},
		})
		s.Require().NoError(err)
		return resp
	}

	cases := []struct {
		name      string
		wantError string // "" means a code
		do        func(c *http.Client, q url.Values) *http.Response
	}{
		{
			name: "authorize: code, consent remembered",
			do: func(c *http.Client, q url.Values) *http.Response {
				resp := consent(c, "allow", q)
				resp.Body.Close()
				s.Require().Equal(http.StatusFound, resp.StatusCode)
				return authorize(c, q)
			},
		},
		{
			name: "consent: code",
			do:   func(c *http.Client, q url.Values) *http.Response { return consent(c, "allow", q) },
		},
		{
			name:      "consent: access_denied",
			wantError: "access_denied",
			do:        func(c *http.Client, q url.Values) *http.Response { return consent(c, "deny", q) },
		},
		{
			name:      "authorize: invalid_scope",
			wantError: "invalid_scope",
			do: func(c *http.Client, q url.Values) *http.Response {
				q.Set("scope", "openid admin:users:read")
				return authorize(c, q)
			},
		},
		{
			name:      "consent: invalid_scope",
			wantError: "invalid_scope",
			do: func(c *http.Client, q url.Values) *http.Response {
				q.Set("scope", "openid admin:users:read")
				return consent(c, "allow", q)
			},
		},
		{
			name:      "authorize: missing PKCE",
			wantError: "invalid_request",
			do: func(c *http.Client, q url.Values) *http.Response {
				q.Del("code_challenge")
				q.Del("code_challenge_method")
				return authorize(c, q)
			},
		},
		{
			name:      "consent: missing PKCE",
			wantError: "invalid_request",
			do: func(c *http.Client, q url.Values) *http.Response {
				q.Del("code_challenge")
				q.Del("code_challenge_method")
				return consent(c, "allow", q)
			},
		},
		{
			name:      "authorize: unsupported_response_type",
			wantError: "unsupported_response_type",
			do: func(c *http.Client, q url.Values) *http.Response {
				q.Set("response_type", "token")
				return authorize(c, q)
			},
		},
		{
			name:      "login page: non-S256 code_challenge_method",
			wantError: "invalid_request",
			do: func(c *http.Client, q url.Values) *http.Response {
				q.Set("code_challenge_method", "plain")
				resp, err := c.Get("http://localhost:8080/oauth/login?" +
					url.Values{"authorize_query": {q.Encode()}}.Encode())
				s.Require().NoError(err)
				return resp
			},
		},
	}

	for _, tc := range cases {
		for _, withState := range []bool{true, false} {
			name := tc.name + " (with state)"
			if !withState {
				name = tc.name + " (no state)"
			}
			s.Run(name, func() {
				s.server.ResetRateLimits()
				httpClient, client := s.mustLoginAndGetAuthorizeClient(db.CreateOAuthClientParams{
					ClientID:      s.mustGenerateRandomString(8),
					Name:          "Iss Client",
					RedirectUris:  []string{callback},
					AllowedScopes: []string{"openid", "profile", "email"},
					Audience:      "test-audience",
				})
				scv := s.mustCreateStateAndCodeVerifier()
				q, err := url.ParseQuery(authorizeQueryFor(client.ClientID, callback, "openid profile", scv, nil))
				s.Require().NoError(err)
				if !withState {
					q.Del("state")
				}

				resp := tc.do(httpClient, q)
				defer resp.Body.Close()

				s.Require().Equal(http.StatusFound, resp.StatusCode)
				loc, err := url.Parse(resp.Header.Get("Location"))
				s.Require().NoError(err)
				s.Require().Equal("localhost:8080", loc.Host, "should redirect to the client, got %s", loc)
				s.Require().Equal("/callback", loc.Path, "should redirect to the client, got %s", loc)

				got := loc.Query()
				s.Equal([]string{testIssuer}, got["iss"], "iss must be the issuer, exactly once")
				if tc.wantError == "" {
					s.NotEmpty(got.Get("code"))
					s.Empty(got.Get("error"))
				} else {
					s.Equal(tc.wantError, got.Get("error"))
					s.Empty(got.Get("code"))
				}
				if withState {
					s.Equal(scv.State, got.Get("state"))
				} else {
					_, hasState := got["state"]
					s.False(hasState, "state must be omitted when the client sent none")
				}
			})
		}
	}
}

// TestErrorsShownByIdentityAreNotRedirects: when the client or redirect_uri
// cannot be trusted there is nothing to redirect to, so identity answers
// itself, and there is no authorization response to carry iss.
func (s *OAuthFlowSuite) TestErrorsShownByIdentityAreNotRedirects() {
	httpClient, client := s.mustLoginAndGetAuthorizeClient(db.CreateOAuthClientParams{
		ClientID:      s.mustGenerateRandomString(8),
		Name:          "Direct Error Client",
		RedirectUris:  []string{"http://localhost:8080/callback"},
		AllowedScopes: []string{"openid"},
		Audience:      "test-audience",
	})
	scv := s.mustCreateStateAndCodeVerifier()

	unknownClient := authorizeQueryFor("no-such-client", "http://localhost:8080/callback", "openid", scv, nil)
	badRedirect := authorizeQueryFor(client.ClientID, "https://evil.example/cb", "openid", scv, nil)

	requests := map[string]func() *http.Response{
		"authorize, unknown client": func() *http.Response {
			resp, err := httpClient.Get("http://localhost:8080/oauth/authorize?" + unknownClient)
			s.Require().NoError(err)
			return resp
		},
		"authorize, unregistered redirect_uri": func() *http.Response {
			resp, err := httpClient.Get("http://localhost:8080/oauth/authorize?" + badRedirect)
			s.Require().NoError(err)
			return resp
		},
		"consent page, unregistered redirect_uri": func() *http.Response {
			resp, err := httpClient.Get("http://localhost:8080/oauth/consent?" +
				url.Values{"authorize_query": {badRedirect}}.Encode())
			s.Require().NoError(err)
			return resp
		},
		"consent page, unknown client": func() *http.Response {
			resp, err := httpClient.Get("http://localhost:8080/oauth/consent?" +
				url.Values{"authorize_query": {unknownClient}}.Encode())
			s.Require().NoError(err)
			return resp
		},
		"consent decision, unregistered redirect_uri": func() *http.Response {
			resp, err := csrfPostFormLogin(s.T(), httpClient, "http://localhost:8080/oauth/consent", url.Values{
				"decision":        {"deny"},
				"authorize_query": {badRedirect},
			})
			s.Require().NoError(err)
			return resp
		},
	}
	for name, do := range requests {
		s.Run(name, func() {
			resp := do()
			defer resp.Body.Close()
			s.Equal(http.StatusBadRequest, resp.StatusCode)
			s.Empty(resp.Header.Get("Location"), "an untrusted redirect_uri must never be redirected to")
		})
	}
}

// TestConsentPageCannotBeFramed: the consent screen is the classic
// clickjacking target, so it refuses every frame.
func (s *OAuthFlowSuite) TestConsentPageCannotBeFramed() {
	httpClient, client := s.mustLoginAndGetAuthorizeClient(db.CreateOAuthClientParams{
		ClientID:      s.mustGenerateRandomString(8),
		Name:          "Frame Client",
		RedirectUris:  []string{"http://localhost:8080/callback"},
		AllowedScopes: []string{"openid"},
		Audience:      "test-audience",
	})
	scv := s.mustCreateStateAndCodeVerifier()
	resp, err := httpClient.Get("http://localhost:8080/oauth/consent?" + url.Values{
		"authorize_query": {authorizeQueryFor(client.ClientID, "http://localhost:8080/callback", "openid", scv, nil)},
	}.Encode())
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Require().Equal(http.StatusOK, resp.StatusCode)
	s.Equal("DENY", resp.Header.Get("X-Frame-Options"))
	s.Equal("frame-ancestors 'none'", resp.Header.Get("Content-Security-Policy"))
}

func (s *OAuthFlowSuite) TestDiscoveryAdvertisesIssParameter() {
	resp, err := s.httpClient.Get("http://localhost:8080/.well-known/openid-configuration")
	s.Require().NoError(err)
	defer resp.Body.Close()
	var doc map[string]any
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&doc))
	s.Equal(true, doc["authorization_response_iss_parameter_supported"])
	s.Equal(testIssuer, doc["issuer"], "the iss on responses is this value")
}

// TestRegisterCarriesTheWholeRequest signs up in the middle of an OAuth flow
// and finishes it: register page -> register -> login page -> login ->
// authorize -> consent -> token. Registration used to carry the request field
// by field and dropped nonce, so the ID token came back without it.
func (s *OAuthFlowSuite) TestRegisterCarriesTheWholeRequest() {
	const callback = "http://localhost:8080/callback"
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:      s.mustGenerateRandomString(8),
		ClientSecret:  sql.NullString{},
		Name:          "Register Flow Client",
		RedirectUris:  []string{callback},
		AllowedScopes: []string{"openid", "profile", "email"},
		Audience:      "test-audience",
	})
	scv := s.mustCreateStateAndCodeVerifier()
	nonce := s.mustGenerateRandomString(24)
	request := authorizeQueryFor(client.ClientID, callback, "openid profile email", scv, url.Values{"nonce": {nonce}})

	jar, err := cookiejar.New(nil)
	s.Require().NoError(err)
	httpClient := &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	// The login page's sign-up link carries the request as one encoded value.
	resp, err := httpClient.Get("http://localhost:8080/oauth/login?" + url.Values{"authorize_query": {request}}.Encode())
	s.Require().NoError(err)
	loginPage, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	s.Require().NoError(err)
	signUp := "/oauth/register?" + url.Values{"authorize_query": {request}}.Encode()
	s.Require().Contains(string(loginPage), `href="`+signUp+`"`)

	// The registration page carries it on.
	resp, err = httpClient.Get("http://localhost:8080" + signUp)
	s.Require().NoError(err)
	registerPage, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	s.Require().NoError(err)
	s.Require().Equal(request, renderedAuthorizeQuery(s.T(), string(registerPage)))
	s.Contains(string(registerPage), `href="/oauth/login?`+url.Values{"authorize_query": {request}}.Encode()+`"`,
		"the sign-in link carries the request too")

	// A refused registration keeps it.
	username := s.mustGenerateAlphanumericString(12)
	password := s.mustGenerateRandomString(16)
	resp, err = csrfPostFormLogin(s.T(), httpClient, "http://localhost:8080/oauth/register", url.Values{
		"username":         {username},
		"email":            {username + "@example.com"},
		"password":         {password},
		"confirm_password": {password + "x"},
		"authorize_query":  {renderedAuthorizeQuery(s.T(), string(registerPage))},
	})
	s.Require().NoError(err)
	refused, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	s.Require().NoError(err)
	s.Require().Equal(http.StatusBadRequest, resp.StatusCode)
	s.Require().Equal(request, renderedAuthorizeQuery(s.T(), string(refused)))

	// Register.
	resp, err = csrfPostFormLogin(s.T(), httpClient, "http://localhost:8080/oauth/register", url.Values{
		"username":         {username},
		"email":            {username + "@example.com"},
		"password":         {password},
		"confirm_password": {password},
		"authorize_query":  {renderedAuthorizeQuery(s.T(), string(refused))},
	})
	s.Require().NoError(err)
	resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	loginLoc, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Require().Equal("/oauth/login", loginLoc.Path)
	s.Require().Equal("true", loginLoc.Query().Get("registered"))
	s.Require().Equal(request, loginLoc.Query().Get("authorize_query"))

	// Sign in from the page registration sent us to.
	resp, err = httpClient.Get("http://localhost:8080" + loginLoc.String())
	s.Require().NoError(err)
	loginPage, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	s.Require().NoError(err)
	resp, err = csrfPostFormLogin(s.T(), httpClient, "http://localhost:8080/oauth/login", url.Values{
		"username":        {username},
		"password":        {password},
		"authorize_query": {renderedAuthorizeQuery(s.T(), string(loginPage))},
	})
	s.Require().NoError(err)
	resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	s.Require().Equal("/oauth/authorize?"+request, resp.Header.Get("Location"),
		"login resumes the original request, not a reconstruction")

	code := s.mustFinishAuthorize(httpClient, resp.Header.Get("Location"))
	idToken := s.mustExchangeForIDToken(client.ClientID, callback, code, scv.CodeVerifier)
	s.Equal(nonce, idTokenClaims(s, idToken)["nonce"], "nonce must survive registration")
}

// TestLoopbackRedirectOnAnyPort is the Claude Code case: a client registered
// with http://localhost/callback (no port) completes a flow from an ephemeral
// port, and the code is redeemed against that concrete URI.
func (s *OAuthFlowSuite) TestLoopbackRedirectOnAnyPort() {
	httpClient, client := s.mustLoginAndGetAuthorizeClient(db.CreateOAuthClientParams{
		ClientID:      s.mustGenerateRandomString(8),
		Name:          "Loopback Client",
		RedirectUris:  []string{"http://localhost/callback", "https://app.example.com/callback"},
		AllowedScopes: []string{"openid"},
		Audience:      "test-audience",
	})
	scv := s.mustCreateStateAndCodeVerifier()
	const ephemeral = "http://localhost:54321/callback"

	resp, err := httpClient.Get("http://localhost:8080/oauth/authorize?" +
		authorizeQueryFor(client.ClientID, ephemeral, "openid", scv, nil))
	s.Require().NoError(err)
	resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)

	code := s.mustFinishAuthorize(httpClient, resp.Header.Get("Location"))
	s.NotEmpty(s.mustExchangeForIDToken(client.ClientID, ephemeral, code, scv.CodeVerifier))

	// The code is bound to the concrete URI: the registered portless form, or
	// another port, does not redeem it.
	for _, other := range []string{"http://localhost/callback", "http://localhost:54322/callback"} {
		scv := s.mustCreateStateAndCodeVerifier()
		resp, err := httpClient.Get("http://localhost:8080/oauth/authorize?" +
			authorizeQueryFor(client.ClientID, ephemeral, "openid", scv, nil))
		s.Require().NoError(err)
		resp.Body.Close()
		code := s.mustFinishAuthorize(httpClient, resp.Header.Get("Location"))
		resp, err = s.httpClient.PostForm("http://localhost:8080/oauth/token", url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {other},
			"client_id":     {client.ClientID},
			"code_verifier": {scv.CodeVerifier},
		})
		s.Require().NoError(err)
		resp.Body.Close()
		s.Equal(http.StatusBadRequest, resp.StatusCode, "redeeming with %s must fail", other)
	}

	// This test makes more requests than the per-IP limit allows in a minute.
	s.server.ResetRateLimits()

	// Refused: a different loopback host, and a port on an https URI.
	for _, candidate := range []string{
		"http://127.0.0.1:54321/callback",
		"http://[::1]:54321/callback",
		"https://app.example.com:8443/callback",
		"https://localhost:54321/callback",
	} {
		scv := s.mustCreateStateAndCodeVerifier()
		resp, err := httpClient.Get("http://localhost:8080/oauth/authorize?" +
			authorizeQueryFor(client.ClientID, candidate, "openid", scv, nil))
		s.Require().NoError(err)
		resp.Body.Close()
		s.Equal(http.StatusBadRequest, resp.StatusCode, "%s must not match", candidate)
		s.Empty(resp.Header.Get("Location"))
	}
}

// TestLogoutHonorsWildcardAndLoopback: post_logout_redirect_uri is matched by
// the same rules as redirect_uri, not an exact list lookup of its own.
func (s *OAuthFlowSuite) TestLogoutHonorsWildcardAndLoopback() {
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID: s.mustGenerateRandomString(8),
		Name:     "Logout Matching Client",
		RedirectUris: []string{
			"https://*.preview.footstrike.run/auth/callback",
			"http://localhost/callback",
		},
		AllowedScopes: []string{"openid"},
		Audience:      "test-audience",
	})

	cases := []struct {
		uri    string
		honors bool
	}{
		{"https://pr-12.preview.footstrike.run/auth/callback", true},
		{"http://localhost:3118/callback", true},
		{"http://localhost/callback", true},
		{"http://127.0.0.1:3118/callback", false},
		{"https://a.b.preview.footstrike.run/auth/callback", false},
		{"https://evil.example/auth/callback", false},
	}
	for _, tc := range cases {
		s.Run(tc.uri, func() {
			resp, err := s.httpClient.Get("http://localhost:8080/oauth/logout?" + url.Values{
				"post_logout_redirect_uri": {tc.uri},
				"client_id":                {client.ClientID},
			}.Encode())
			s.Require().NoError(err)
			resp.Body.Close()
			s.Require().Equal(http.StatusFound, resp.StatusCode)
			if tc.honors {
				s.Equal(tc.uri, resp.Header.Get("Location"))
			} else {
				s.Equal("/oauth/login", resp.Header.Get("Location"))
			}
		})
	}
}

// mustFinishAuthorize follows an /oauth/authorize redirect for a signed-in
// client through consent (approving it) and returns the code the client
// receives, checking the response's iss on the way.
func (s *OAuthFlowSuite) mustFinishAuthorize(httpClient *http.Client, location string) string {
	s.T().Helper()
	if strings.HasPrefix(location, "/oauth/authorize") {
		resp, err := httpClient.Get("http://localhost:8080" + location)
		s.Require().NoError(err)
		resp.Body.Close()
		s.Require().Equal(http.StatusFound, resp.StatusCode)
		location = resp.Header.Get("Location")
	}
	if strings.HasPrefix(location, "/oauth/consent") {
		resp, err := csrfPostFormLogin(s.T(), httpClient, "http://localhost:8080/oauth/consent",
			consentFormFrom(s.T(), location, "allow"))
		s.Require().NoError(err)
		resp.Body.Close()
		s.Require().Equal(http.StatusFound, resp.StatusCode)
		location = resp.Header.Get("Location")
	}
	loc, err := url.Parse(location)
	s.Require().NoError(err)
	s.Require().Equal(testIssuer, loc.Query().Get("iss"))
	code := loc.Query().Get("code")
	s.Require().NotEmpty(code, "expected a code at the client, got %s", location)
	return code
}

// mustExchangeForIDToken redeems a public client's code and returns the ID token.
func (s *OAuthFlowSuite) mustExchangeForIDToken(clientID, redirectURI, code, verifier string) string {
	s.T().Helper()
	resp, err := s.httpClient.PostForm("http://localhost:8080/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {verifier},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, resp.StatusCode, "token exchange: %s", body)
	var tr TokenResponse
	s.Require().NoError(json.Unmarshal(body, &tr))
	s.Require().NotEmpty(tr.IDToken)
	return tr.IDToken
}

// idTokenClaims decodes a JWT's payload without verifying it.
func idTokenClaims(s *OAuthFlowSuite, token string) map[string]any {
	parts := strings.Split(token, ".")
	s.Require().Len(parts, 3, fmt.Sprintf("not a JWT: %q", token))
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	s.Require().NoError(err)
	var claims map[string]any
	s.Require().NoError(json.Unmarshal(payload, &claims))
	return claims
}
