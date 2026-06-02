//go:build integration

package httpserver

import (
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"

	"github.com/eswan18/identity/pkg/db"
)

// TestLogoutAcceptsGET verifies that the logout endpoint (advertised as
// end_session_endpoint in OIDC discovery) accepts GET requests per OIDC
// RP-Initiated Logout 1.0, which expects browsers to navigate to it via redirect.
func (s *OAuthFlowSuite) TestLogoutAcceptsGET() {
	resp, err := s.httpClient.Get("http://localhost:8080/oauth/logout")
	s.Require().NoError(err)
	defer resp.Body.Close()
	// Without a session cookie, we still expect a redirect to the login page
	// rather than a 404/405. That's the signal that GET is wired up.
	s.Equal(http.StatusFound, resp.StatusCode)
}

func (s *OAuthFlowSuite) TestSuccessPageRequiresAuthentication() {
	// Unauthenticated request to /oauth/success should redirect to login
	resp, err := s.httpClient.Get("http://localhost:8080/oauth/success")
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusFound, resp.StatusCode)
	s.Equal("/oauth/login", resp.Header.Get("Location"))
}

func (s *OAuthFlowSuite) TestSuccessPageRendersWhenAuthenticated() {
	// Log in first to get a session
	username := s.mustGenerateRandomString(8)
	password := s.mustGenerateRandomString(16)
	s.mustRegisterUser(username, password, fmt.Sprintf("%s@example.com", username))

	jar, err := cookiejar.New(nil)
	s.Require().NoError(err)
	httpClient := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Login to establish a session
	resp, err := httpClient.PostForm("http://localhost:8080/oauth/login", url.Values{
		"username": {username},
		"password": {password},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)

	// Now access /oauth/success — should render the page
	resp, err = httpClient.Get("http://localhost:8080/oauth/success")
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusOK, resp.StatusCode)
}

// Authorize Error Redirect Tests
//
// Per RFC 6749 4.1.2.1, when the redirect_uri is valid and the client is known,
// errors should be redirected back to the client as query parameters.
// When the client or redirect_uri is invalid/unknown, errors must be shown directly.

func (s *OAuthFlowSuite) TestAuthorizeInvalidScopeRedirectsErrorToClient() {
	httpClient, client := s.mustLoginAndGetAuthorizeClient(db.CreateOAuthClientParams{
		ClientID:       "authz-error-scope-client",
		Name:           "Authz Error Scope Client",
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid"},
		IsConfidential: false,
		Audience:       "test-audience",
	})
	scv := s.mustCreateStateAndCodeVerifier()

	// Request a scope the client doesn't support
	query := url.Values{
		"client_id":             {client.ClientID},
		"redirect_uri":          {"http://localhost:8080/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid admin:users:read"},
		"state":                 {scv.State},
		"code_challenge":        {scv.CodeChallenge},
		"code_challenge_method": {scv.CodeChallengeMethod},
	}
	resp, err := httpClient.Get("http://localhost:8080/oauth/authorize?" + query.Encode())
	s.Require().NoError(err)
	defer resp.Body.Close()

	// Should redirect back to the client with error params, not show a raw error page
	s.Equal(http.StatusFound, resp.StatusCode)
	location, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Equal("/callback", location.Path)
	s.Equal("invalid_scope", location.Query().Get("error"))
	s.Equal(scv.State, location.Query().Get("state"))
}

func (s *OAuthFlowSuite) TestAuthorizeMissingPKCERedirectsErrorToClient() {
	httpClient, client := s.mustLoginAndGetAuthorizeClient(db.CreateOAuthClientParams{
		ClientID:       "authz-error-pkce-client",
		Name:           "Authz Error PKCE Client",
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid"},
		IsConfidential: false,
		Audience:       "test-audience",
	})

	// Omit code_challenge and code_challenge_method
	query := url.Values{
		"client_id":     {client.ClientID},
		"redirect_uri":  {"http://localhost:8080/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
		"state":         {"test-state"},
	}
	resp, err := httpClient.Get("http://localhost:8080/oauth/authorize?" + query.Encode())
	s.Require().NoError(err)
	defer resp.Body.Close()

	// Should redirect back to client with error, not show a raw error page
	s.Equal(http.StatusFound, resp.StatusCode)
	location, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Equal("/callback", location.Path)
	s.Equal("invalid_request", location.Query().Get("error"))
	s.Equal("test-state", location.Query().Get("state"))
}

func (s *OAuthFlowSuite) TestAuthorizeInvalidResponseTypeRedirectsErrorToClient() {
	httpClient, client := s.mustLoginAndGetAuthorizeClient(db.CreateOAuthClientParams{
		ClientID:       "authz-error-rt-client",
		Name:           "Authz Error RT Client",
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid"},
		IsConfidential: false,
		Audience:       "test-audience",
	})

	scv := s.mustCreateStateAndCodeVerifier()
	// Use an unsupported response_type
	query := url.Values{
		"client_id":             {client.ClientID},
		"redirect_uri":          {"http://localhost:8080/callback"},
		"response_type":         {"token"},
		"scope":                 {"openid"},
		"state":                 {scv.State},
		"code_challenge":        {scv.CodeChallenge},
		"code_challenge_method": {scv.CodeChallengeMethod},
	}
	resp, err := httpClient.Get("http://localhost:8080/oauth/authorize?" + query.Encode())
	s.Require().NoError(err)
	defer resp.Body.Close()

	// Should redirect back to client with error
	s.Equal(http.StatusFound, resp.StatusCode)
	location, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Equal("/callback", location.Path)
	s.Equal("unsupported_response_type", location.Query().Get("error"))
	s.Equal(scv.State, location.Query().Get("state"))
}

func (s *OAuthFlowSuite) TestAuthorizeInvalidClientShowsDirectError() {
	// Login first to get a session, using a dummy client
	httpClient, _ := s.mustLoginAndGetAuthorizeClient(db.CreateOAuthClientParams{
		ClientID:       "authz-dummy-client",
		Name:           "Dummy Client",
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid"},
		IsConfidential: false,
		Audience:       "test-audience",
	})

	// Now try to authorize with a nonexistent client — can't trust the redirect_uri
	query := url.Values{
		"client_id":             {"nonexistent-client"},
		"redirect_uri":          {"http://evil.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"state":                 {"test-state"},
		"code_challenge":        {"challenge"},
		"code_challenge_method": {"S256"},
	}
	resp, err := httpClient.Get("http://localhost:8080/oauth/authorize?" + query.Encode())
	s.Require().NoError(err)
	defer resp.Body.Close()

	// Should NOT redirect to the untrusted URI — show error directly
	s.Equal(http.StatusBadRequest, resp.StatusCode)
}

func (s *OAuthFlowSuite) TestAuthorizeInvalidRedirectURIShowsDirectError() {
	httpClient, client := s.mustLoginAndGetAuthorizeClient(db.CreateOAuthClientParams{
		ClientID:       "authz-error-redir-client",
		Name:           "Authz Error Redir Client",
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid"},
		IsConfidential: false,
		Audience:       "test-audience",
	})

	// Use a redirect_uri that's NOT registered for this client
	query := url.Values{
		"client_id":             {client.ClientID},
		"redirect_uri":          {"http://evil.com/steal-tokens"},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"state":                 {"test-state"},
		"code_challenge":        {"challenge"},
		"code_challenge_method": {"S256"},
	}
	resp, err := httpClient.Get("http://localhost:8080/oauth/authorize?" + query.Encode())
	s.Require().NoError(err)
	defer resp.Body.Close()

	// Should NOT redirect to the untrusted URI — show error directly
	s.Equal(http.StatusBadRequest, resp.StatusCode)
}

func (s *OAuthFlowSuite) TestConsentScreenShownOnFirstAuthorize() {
	httpClient, client := s.mustLoginAndGetAuthorizeClient(db.CreateOAuthClientParams{
		ClientID:       "consent-test-client",
		Name:           "Consent Test App",
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid", "profile", "email"},
		IsConfidential: false,
		Audience:       "test-audience",
	})
	scv := s.mustCreateStateAndCodeVerifier()

	query := url.Values{
		"client_id":             {client.ClientID},
		"redirect_uri":          {"http://localhost:8080/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid profile email"},
		"state":                 {scv.State},
		"code_challenge":        {scv.CodeChallenge},
		"code_challenge_method": {scv.CodeChallengeMethod},
	}
	resp, err := httpClient.Get("http://localhost:8080/oauth/authorize?" + query.Encode())
	s.Require().NoError(err)
	defer resp.Body.Close()

	// Should redirect to consent page, not directly to client
	s.Equal(http.StatusFound, resp.StatusCode)
	location, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Equal("/oauth/consent", location.Path)
}

func (s *OAuthFlowSuite) TestConsentApproveGeneratesCode() {
	httpClient, client := s.mustLoginAndGetAuthorizeClient(db.CreateOAuthClientParams{
		ClientID:       "consent-approve-client",
		Name:           "Consent Approve App",
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid", "profile", "email"},
		IsConfidential: false,
		Audience:       "test-audience",
	})
	scv := s.mustCreateStateAndCodeVerifier()

	// POST consent approval
	resp, err := httpClient.PostForm("http://localhost:8080/oauth/consent", url.Values{
		"decision":              {"allow"},
		"client_id":             {client.ClientID},
		"redirect_uri":          {"http://localhost:8080/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid profile email"},
		"state":                 {scv.State},
		"code_challenge":        {scv.CodeChallenge},
		"code_challenge_method": {scv.CodeChallengeMethod},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()

	// Should redirect to client with authorization code
	s.Equal(http.StatusFound, resp.StatusCode)
	location, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Equal("/callback", location.Path)
	s.NotEmpty(location.Query().Get("code"), "should have authorization code")
	s.Equal(scv.State, location.Query().Get("state"))
}

func (s *OAuthFlowSuite) TestConsentDenyRedirectsWithError() {
	httpClient, client := s.mustLoginAndGetAuthorizeClient(db.CreateOAuthClientParams{
		ClientID:       "consent-deny-client",
		Name:           "Consent Deny App",
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid"},
		IsConfidential: false,
		Audience:       "test-audience",
	})
	scv := s.mustCreateStateAndCodeVerifier()

	// POST consent denial
	resp, err := httpClient.PostForm("http://localhost:8080/oauth/consent", url.Values{
		"decision":              {"deny"},
		"client_id":             {client.ClientID},
		"redirect_uri":          {"http://localhost:8080/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"state":                 {scv.State},
		"code_challenge":        {scv.CodeChallenge},
		"code_challenge_method": {scv.CodeChallengeMethod},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()

	// Should redirect to client with access_denied error
	s.Equal(http.StatusFound, resp.StatusCode)
	location, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Equal("/callback", location.Path)
	s.Equal("access_denied", location.Query().Get("error"))
	s.Equal(scv.State, location.Query().Get("state"))
}

func (s *OAuthFlowSuite) TestConsentRemembered() {
	httpClient, client := s.mustLoginAndGetAuthorizeClient(db.CreateOAuthClientParams{
		ClientID:       "consent-remember-client",
		Name:           "Consent Remember App",
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid", "profile", "email"},
		IsConfidential: false,
		Audience:       "test-audience",
	})
	scv := s.mustCreateStateAndCodeVerifier()

	// First: approve consent
	resp, err := httpClient.PostForm("http://localhost:8080/oauth/consent", url.Values{
		"decision":              {"allow"},
		"client_id":             {client.ClientID},
		"redirect_uri":          {"http://localhost:8080/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid profile email"},
		"state":                 {scv.State},
		"code_challenge":        {scv.CodeChallenge},
		"code_challenge_method": {scv.CodeChallengeMethod},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)

	// Second: authorize again with same scopes — should skip consent
	scv2 := s.mustCreateStateAndCodeVerifier()
	query := url.Values{
		"client_id":             {client.ClientID},
		"redirect_uri":          {"http://localhost:8080/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid profile email"},
		"state":                 {scv2.State},
		"code_challenge":        {scv2.CodeChallenge},
		"code_challenge_method": {scv2.CodeChallengeMethod},
	}
	resp, err = httpClient.Get("http://localhost:8080/oauth/authorize?" + query.Encode())
	s.Require().NoError(err)
	defer resp.Body.Close()

	// Should go directly to client with code (consent remembered)
	s.Equal(http.StatusFound, resp.StatusCode)
	location, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Equal("/callback", location.Path, "should redirect to client, not consent page")
	s.NotEmpty(location.Query().Get("code"), "should have authorization code")
}

func (s *OAuthFlowSuite) TestConsentRePromptedForNewScopes() {
	httpClient, client := s.mustLoginAndGetAuthorizeClient(db.CreateOAuthClientParams{
		ClientID:       "consent-reprompt-client",
		Name:           "Consent Reprompt App",
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid", "profile", "email"},
		IsConfidential: false,
		Audience:       "test-audience",
	})
	scv := s.mustCreateStateAndCodeVerifier()

	// First: approve consent for openid only
	resp, err := httpClient.PostForm("http://localhost:8080/oauth/consent", url.Values{
		"decision":              {"allow"},
		"client_id":             {client.ClientID},
		"redirect_uri":          {"http://localhost:8080/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"state":                 {scv.State},
		"code_challenge":        {scv.CodeChallenge},
		"code_challenge_method": {scv.CodeChallengeMethod},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)

	// Second: authorize with openid + email — new scope, should show consent again
	scv2 := s.mustCreateStateAndCodeVerifier()
	query := url.Values{
		"client_id":             {client.ClientID},
		"redirect_uri":          {"http://localhost:8080/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid email"},
		"state":                 {scv2.State},
		"code_challenge":        {scv2.CodeChallenge},
		"code_challenge_method": {scv2.CodeChallengeMethod},
	}
	resp, err = httpClient.Get("http://localhost:8080/oauth/authorize?" + query.Encode())
	s.Require().NoError(err)
	defer resp.Body.Close()

	// Should redirect to consent page (new scope requested)
	s.Equal(http.StatusFound, resp.StatusCode)
	location, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Equal("/oauth/consent", location.Path, "should show consent for new scopes")
}

func (s *OAuthFlowSuite) TestLogoutRedirectsToLoginByDefault() {
	resp, err := s.httpClient.Post("http://localhost:8080/oauth/logout", "", nil)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusFound, resp.StatusCode)
	s.Equal("/oauth/login", resp.Header.Get("Location"))
}

func (s *OAuthFlowSuite) TestLogoutWithValidPostLogoutRedirectURI() {
	// Register a client with a known redirect URI
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       "logout-test-client",
		Name:           "Logout Test Client",
		RedirectUris:   []string{"http://example.com/callback"},
		AllowedScopes:  []string{"openid"},
		IsConfidential: false,
		Audience:       "test-audience",
	})

	// Logout with a valid post_logout_redirect_uri and client_id
	resp, err := s.httpClient.Post(
		"http://localhost:8080/oauth/logout?post_logout_redirect_uri=http://example.com/callback&client_id="+client.ClientID,
		"", nil,
	)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusFound, resp.StatusCode)
	s.Equal("http://example.com/callback", resp.Header.Get("Location"))
}

func (s *OAuthFlowSuite) TestLogoutRejectsUnregisteredPostLogoutRedirectURI() {
	// Register a client with a known redirect URI
	s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       "logout-reject-client",
		Name:           "Logout Reject Client",
		RedirectUris:   []string{"http://example.com/callback"},
		AllowedScopes:  []string{"openid"},
		IsConfidential: false,
		Audience:       "test-audience",
	})

	// Logout with a redirect URI that is NOT in the client's registered URIs
	resp, err := s.httpClient.Post(
		"http://localhost:8080/oauth/logout?post_logout_redirect_uri=https://evil.com/phishing&client_id=logout-reject-client",
		"", nil,
	)
	s.Require().NoError(err)
	defer resp.Body.Close()

	// Should ignore the invalid URI and redirect to login
	s.Equal(http.StatusFound, resp.StatusCode)
	s.Equal("/oauth/login", resp.Header.Get("Location"))
}

func (s *OAuthFlowSuite) TestLogoutRejectsPostLogoutRedirectURIWithUnknownClientID() {
	// Providing a client_id that doesn't exist should fall back to login
	resp, err := s.httpClient.Post(
		"http://localhost:8080/oauth/logout?post_logout_redirect_uri=http://example.com/callback&client_id=nonexistent-client",
		"", nil,
	)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusFound, resp.StatusCode)
	s.Equal("/oauth/login", resp.Header.Get("Location"))
}

func (s *OAuthFlowSuite) TestLogoutRejectsPostLogoutRedirectURIWithoutClientID() {
	// Providing post_logout_redirect_uri without client_id should fall back to login
	resp, err := s.httpClient.Post(
		"http://localhost:8080/oauth/logout?post_logout_redirect_uri=http://example.com/callback",
		"", nil,
	)
	s.Require().NoError(err)
	defer resp.Body.Close()

	// Without client_id, can't validate the URI, so redirect to login
	s.Equal(http.StatusFound, resp.StatusCode)
	s.Equal("/oauth/login", resp.Header.Get("Location"))
}
