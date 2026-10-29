//go:build integration

package httpserver

import (
	"database/sql"
	"net/http"
	"net/url"
	"strings"

	"github.com/eswan18/identity/pkg/db"
	"github.com/eswan18/identity/pkg/mfa"
)

// Trusted (first-party) clients skip the consent screen and nothing else
// (README, "Trusted (first-party) clients"): login, MFA, redirect-URI
// validation, PKCE, scope checks and the deactivated-account check all still
// apply, no consent row is written, and the Connected Apps page never lists
// one.

// trustedClientParams is a trusted public client with a recognizable name.
func (s *OAuthFlowSuite) trustedClientParams(name string) db.CreateOAuthClientParams {
	params := s.connectedAppsClientParams(name)
	params.Trusted = true
	return params
}

// userConsentCount is how many consent rows user has for client.
func (s *OAuthFlowSuite) userConsentCount(user UserWithPassword, client db.OauthClient) int {
	s.T().Helper()
	var n int
	s.Require().NoError(s.datastore.DB.QueryRowContext(s.T().Context(),
		`SELECT count(*) FROM oauth_user_consents WHERE user_id = $1 AND client_id = $2`,
		user.ID, client.ID).Scan(&n))
	return n
}

// newTestUser registers a user with a random name and password.
func (s *OAuthFlowSuite) newTestUser() UserWithPassword {
	return s.mustRegisterUser(s.mustGenerateAlphanumericString(10), s.mustGenerateRandomString(16),
		s.mustGenerateAlphanumericString(10)+"@example.com")
}

// A trusted client's flow: signed out, authorize sends the user to login;
// after login, authorize issues a code straight away with no consent screen;
// the code exchanges for tokens with the right PKCE verifier and not with a
// wrong one; and no consent row is written.
func (s *OAuthFlowSuite) TestTrustedClient_SkipsConsentButStillRequiresLogin() {
	client := s.mustRegisterOAuthClient(s.trustedClientParams("First Party"))
	s.Require().True(client.Trusted)
	user := s.newTestUser()
	scv := s.mustCreateStateAndCodeVerifier()
	query := authorizeQueryFor(client.ClientID, client.RedirectUris[0], "openid profile email", scv, nil)
	browser := s.newBrowser()

	// Signed out: login first, never a code.
	resp := s.get(browser, testBaseURL+"/oauth/authorize?"+query)
	resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	s.True(strings.HasPrefix(resp.Header.Get("Location"), "/oauth/login?"),
		"a trusted client still needs a signed-in user, got %s", resp.Header.Get("Location"))

	resp, err := csrfPostFormLogin(s.T(), browser, testBaseURL+"/oauth/login", url.Values{
		"username": {user.Username}, "password": {user.Password}, "authorize_query": {query},
	})
	s.Require().NoError(err)
	resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	authorizeURL := resp.Header.Get("Location")
	s.Require().True(strings.HasPrefix(authorizeURL, "/oauth/authorize?"), "login returns to authorize, got %s", authorizeURL)

	// Signed in: a code, not the consent page.
	code := s.requireCode(s.get(browser, testBaseURL+authorizeURL))
	s.Zero(s.userConsentCount(user, client), "no consent row is written for a trusted client")

	// A wrong verifier is refused; PKCE applies as to any client.
	wrong := scv
	wrong.CodeVerifier = s.mustGenerateRandomString(32)
	status, body := s.postTokenForm(exchangeForm(client, code, wrong, nil))
	s.Equal(http.StatusBadRequest, status)
	s.Equal("invalid_grant", body["error"])

	// A fresh code with the right verifier exchanges for tokens as before.
	scv = s.mustCreateStateAndCodeVerifier()
	query = authorizeQueryFor(client.ClientID, client.RedirectUris[0], "openid profile email", scv, nil)
	code = s.requireCode(s.get(browser, testBaseURL+"/oauth/authorize?"+query))
	status, body = s.postTokenForm(exchangeForm(client, code, scv, nil))
	s.Require().Equal(http.StatusOK, status, "token exchange: %v", body)
	s.NotEmpty(body["access_token"])
	s.NotEmpty(body["refresh_token"])
	s.NotEmpty(body["id_token"])
	s.mustRefresh(client, body["refresh_token"].(string))
	s.Zero(s.userConsentCount(user, client))

	// And it never appears on the Connected Apps page.
	page := s.mustGetPage(browser, connectedAppsURL)
	s.NotContains(page, client.Name)
	s.Contains(page, "No apps are connected to your account.")
}

// MFA still applies: login sends a user with MFA to the challenge, and only
// after it does authorize issue the code.
func (s *OAuthFlowSuite) TestTrustedClient_StillRequiresMFA() {
	client := s.mustRegisterOAuthClient(s.trustedClientParams("First Party MFA"))
	user := s.newTestUser()
	key, err := mfa.GenerateSecret(user.Username)
	s.Require().NoError(err)
	secret := mfa.GetSecret(key)
	s.mustEnableMFAForUser(user, secret)
	scv := s.mustCreateStateAndCodeVerifier()
	query := authorizeQueryFor(client.ClientID, client.RedirectUris[0], "openid", scv, nil)
	browser := s.newBrowser()

	resp, err := csrfPostFormLogin(s.T(), browser, testBaseURL+"/oauth/login", url.Values{
		"username": {user.Username}, "password": {user.Password}, "authorize_query": {query},
	})
	s.Require().NoError(err)
	resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	mfaURL, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Require().Equal("/oauth/mfa", mfaURL.Path, "a trusted client does not skip MFA")

	// Before MFA there is no session: authorize still sends the user to login.
	resp = s.get(browser, testBaseURL+"/oauth/authorize?"+query)
	resp.Body.Close()
	s.True(strings.HasPrefix(resp.Header.Get("Location"), "/oauth/login?"), "no code before MFA")

	totp, err := generateTOTPCode(secret)
	s.Require().NoError(err)
	resp, err = csrfPostFormLogin(s.T(), browser, testBaseURL+"/oauth/mfa", url.Values{
		"pending_id": {mfaURL.Query().Get("pending")}, "code": {totp},
	})
	s.Require().NoError(err)
	resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	authorizeURL := resp.Header.Get("Location")
	s.Require().True(strings.HasPrefix(authorizeURL, "/oauth/authorize?"), "MFA returns to authorize, got %s", authorizeURL)
	code := s.requireCode(s.get(browser, testBaseURL+authorizeURL))
	status, body := s.postTokenForm(exchangeForm(client, code, scv, nil))
	s.Equal(http.StatusOK, status, "token exchange: %v", body)
}

// The request checks before consent are the same for a trusted client: an
// unregistered redirect_uri is refused without a redirect, a missing PKCE
// challenge and a scope the client may not have are refused to the client,
// and a deactivated account is bounced to login.
func (s *OAuthFlowSuite) TestTrustedClient_RequestChecksStillApply() {
	client := s.mustRegisterOAuthClient(s.trustedClientParams("First Party Checks"))
	user := s.newTestUser()
	browser := s.mustSignInAs(user)
	scv := s.mustCreateStateAndCodeVerifier()

	// Unregistered redirect_uri: an error page, never a redirect to it.
	query := authorizeQueryFor(client.ClientID, "https://evil.example/callback", "openid", scv, nil)
	resp := s.get(browser, testBaseURL+"/oauth/authorize?"+query)
	resp.Body.Close()
	s.Equal(http.StatusBadRequest, resp.StatusCode)
	s.Empty(resp.Header.Get("Location"))

	// No PKCE challenge.
	q := url.Values{
		"response_type": {"code"}, "client_id": {client.ClientID},
		"redirect_uri": {client.RedirectUris[0]}, "scope": {"openid"}, "state": {scv.State},
	}
	s.requireClientError(s.get(browser, testBaseURL+"/oauth/authorize?"+q.Encode()), "invalid_request")

	// A scope the client is not registered for.
	query = authorizeQueryFor(client.ClientID, client.RedirectUris[0], "openid admin:users", scv, nil)
	s.requireClientError(s.get(browser, testBaseURL+"/oauth/authorize?"+query), "invalid_scope")

	// A deactivated account gets no code.
	s.Require().NoError(s.datastore.Q.DeactivateUser(s.T().Context(), user.ID))
	query = authorizeQueryFor(client.ClientID, client.RedirectUris[0], "openid", scv, nil)
	resp = s.get(browser, testBaseURL+"/oauth/authorize?"+query)
	resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	location, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Equal("/oauth/login", location.Path)
	s.Equal("account_deactivated", location.Query().Get("error"))
}

// The consent endpoints for a trusted client: the page is never rendered (the
// GET goes back to authorize), and a POST mints a code after the same checks
// but writes no consent row.
func (s *OAuthFlowSuite) TestTrustedClient_ConsentEndpoints() {
	client := s.mustRegisterOAuthClient(s.trustedClientParams("First Party Consent"))
	user := s.newTestUser()
	browser := s.mustSignInAs(user)
	scv := s.mustCreateStateAndCodeVerifier()
	query := authorizeQueryFor(client.ClientID, client.RedirectUris[0], "openid", scv, nil)

	resp := s.get(browser, testBaseURL+"/oauth/consent?"+url.Values{"authorize_query": {query}}.Encode())
	resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	s.True(strings.HasPrefix(resp.Header.Get("Location"), "/oauth/authorize?"), "got %s", resp.Header.Get("Location"))

	resp, err := csrfPostFormLogin(s.T(), browser, testBaseURL+"/oauth/consent", url.Values{
		"decision": {"allow"}, "authorize_query": {query},
	})
	s.Require().NoError(err)
	s.requireCode(resp)
	s.Zero(s.userConsentCount(user, client), "a POST for a trusted client stores no consent")
}

// An untrusted client is unchanged: authorize sends a signed-in user to the
// consent screen, and approving it stores a consent.
func (s *OAuthFlowSuite) TestUntrustedClient_StillAsksForConsent() {
	client := s.mustRegisterOAuthClient(s.connectedAppsClientParams("Third Party"))
	s.Require().False(client.Trusted, "clients are untrusted by default")
	user := s.newTestUser()
	browser := s.mustSignInAs(user)
	query := authorizeQueryFor(client.ClientID, client.RedirectUris[0], "openid", s.mustCreateStateAndCodeVerifier(), nil)
	consentURL := s.requireConsentRedirect(s.get(browser, testBaseURL+"/oauth/authorize?"+query))
	s.mustApprove(browser, consentURL)
	s.Equal(1, s.userConsentCount(user, client))
}

// A client trusted after users consented to it disappears from their
// Connected Apps page, though the old consent rows are still there, and
// cannot be disconnected from it either.
func (s *OAuthFlowSuite) TestConnectedApps_HidesTrustedClientsWithOldConsents() {
	flow := s.mustCompleteOAuthFlow(s.connectedAppsClientParams("Later Trusted"))
	s.server.ResetRateLimits()
	browser := s.mustSignInAs(flow.User)
	s.Contains(s.mustGetPage(browser, connectedAppsURL), flow.Client.Name, "listed while untrusted")

	_, err := s.datastore.Q.UpdateOAuthClient(s.T().Context(), db.UpdateOAuthClientParams{
		ClientID: flow.Client.ClientID,
		Trusted:  sql.NullBool{Bool: true, Valid: true},
	})
	s.Require().NoError(err)
	s.Require().True(s.hasConsent(flow.User, flow.Client), "the old consent row is still there")

	page := s.mustGetPage(browser, connectedAppsURL)
	s.NotContains(page, flow.Client.Name, "a trusted client is never listed")
	s.Contains(page, "No apps are connected to your account.")

	location := s.postDisconnect(browser, url.Values{"client": {flow.Client.ID.String()}, "confirm": {"yes"}})
	s.Equal("/oauth/connected-apps?error=not_connected", location)
	s.False(s.tokenRow(flow.TokenResponse.RefreshToken).RevokedAt.Valid, "nothing is revoked")
}
