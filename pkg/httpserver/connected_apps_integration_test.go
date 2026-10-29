//go:build integration

package httpserver

import (
	"database/sql"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"

	"github.com/eswan18/identity/pkg/db"
	"github.com/eswan18/identity/pkg/mfa"
)

// The connected-apps page: listing, disconnecting, and the signed-out
// round trip through login (and MFA) back to it.

const connectedAppsURL = testBaseURL + "/oauth/connected-apps"

// connectedAppsClientParams is a public client with a recognizable name.
func (s *OAuthFlowSuite) connectedAppsClientParams(name string) db.CreateOAuthClientParams {
	return db.CreateOAuthClientParams{
		ClientID:        s.mustGenerateRandomString(12),
		Name:            name + " " + s.mustGenerateAlphanumericString(8),
		RedirectUris:    []string{"http://localhost:8080/callback"},
		AllowedScopes:   []string{"openid", "profile", "email"},
		IsConfidential:  false,
		DefaultResource: testResource("https://connected-apps.example"),
	}
}

// newBrowser is a cookie-keeping client that does not follow redirects.
func (s *OAuthFlowSuite) newBrowser() *http.Client {
	jar, err := cookiejar.New(nil)
	s.Require().NoError(err)
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// mustSignInAs signs user in directly (no OAuth flow, no MFA) in a new browser.
func (s *OAuthFlowSuite) mustSignInAs(user UserWithPassword) *http.Client {
	s.T().Helper()
	browser := s.newBrowser()
	resp, err := csrfPostFormLogin(s.T(), browser, testBaseURL+"/oauth/login", url.Values{
		"username": {user.Username},
		"password": {user.Password},
	})
	s.Require().NoError(err)
	resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	return browser
}

// mustGetPage GETs url and requires 200, returning the body.
func (s *OAuthFlowSuite) mustGetPage(browser *http.Client, pageURL string) string {
	s.T().Helper()
	resp, err := browser.Get(pageURL)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode, "GET %s", pageURL)
	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	return string(body)
}

// postDisconnect submits the disconnect form and returns the redirect target.
func (s *OAuthFlowSuite) postDisconnect(browser *http.Client, form url.Values) string {
	s.T().Helper()
	resp, err := csrfPostForm(s.T(), browser, connectedAppsURL, connectedAppsURL+"/disconnect", form)
	s.Require().NoError(err)
	resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	return resp.Header.Get("Location")
}

// hasConsent reports whether user has any consent for client.
func (s *OAuthFlowSuite) hasConsent(user UserWithPassword, client db.OauthClient) bool {
	s.T().Helper()
	var n int
	s.Require().NoError(s.datastore.DB.QueryRowContext(s.T().Context(),
		`SELECT count(*) FROM oauth_user_consents WHERE user_id = $1 AND client_id = $2`,
		user.ID, client.ID).Scan(&n))
	return n > 0
}

func (s *OAuthFlowSuite) TestConnectedApps_ListsOnlyTheUsersOwnApps() {
	mine := s.mustCompleteOAuthFlow(s.connectedAppsClientParams("Mine"))
	theirs := s.mustCompleteOAuthFlow(s.connectedAppsClientParams("Theirs"))
	s.server.ResetRateLimits()

	page := s.mustGetPage(s.mustSignInAs(mine.User), connectedAppsURL)

	s.Contains(page, mine.Client.Name)
	s.Contains(page, "Verify your identity", "scope descriptions are the consent screen's")
	s.Contains(page, "connected-apps.example", "the resource is named")
	s.Contains(page, mine.Client.ID.String(), "the disconnect form names the client")
	s.NotContains(page, theirs.Client.Name, "another user's app must never be shown")
	s.NotContains(page, theirs.Client.ID.String())
	s.NotContains(page, "Not recorded", "a token was issued, so last use is known")
	s.NotContains(page, "No apps are connected")
}

func (s *OAuthFlowSuite) TestConnectedApps_EmptyState() {
	user := s.mustRegisterUser(s.mustGenerateAlphanumericString(10), s.mustGenerateRandomString(16),
		s.mustGenerateAlphanumericString(10)+"@example.com")
	page := s.mustGetPage(s.mustSignInAs(user), connectedAppsURL)
	s.Contains(page, "No apps are connected to your account.")
	s.NotContains(page, "/oauth/connected-apps/disconnect")
}

func (s *OAuthFlowSuite) TestConnectedApps_DisconnectRevokesTokensAndForgetsConsent() {
	flow := s.mustCompleteOAuthFlow(s.connectedAppsClientParams("Gone"))
	user, client := flow.User, flow.Client
	// A second app for the same user, which must be left alone.
	other := s.mustRegisterOAuthClient(s.connectedAppsClientParams("Kept"))
	s.mustLoginAndConsent(user, other.ClientID, other.RedirectUris[0], "openid", s.mustCreateStateAndCodeVerifier())
	s.server.ResetRateLimits()

	// A second live token for the disconnected app, by refreshing.
	refreshed := s.mustRefresh(client, flow.TokenResponse.RefreshToken)
	s.Require().True(s.hasConsent(user, client))

	browser := s.mustSignInAs(user)
	location := s.postDisconnect(browser, url.Values{"client": {client.ID.String()}, "confirm": {"yes"}})
	s.Equal("/oauth/connected-apps?success=disconnected", location)

	// The consent is gone; the other app's is not.
	s.False(s.hasConsent(user, client), "disconnecting forgets the consent")
	s.True(s.hasConsent(user, other), "only the named app is disconnected")

	// Every token the user held for it is revoked, with the reason recorded.
	row := s.tokenRow(refreshed.RefreshToken)
	s.True(row.RevokedAt.Valid, "the live token is revoked")
	s.Equal("user_disconnected", row.RevokedReason.String)
	var live int
	s.Require().NoError(s.datastore.DB.QueryRowContext(s.T().Context(),
		`SELECT count(*) FROM oauth_tokens WHERE user_id = $1 AND client_id = $2 AND revoked_at IS NULL`,
		user.ID, client.ID).Scan(&live))
	s.Zero(live, "no live token remains for the app")
	_, err := s.datastore.Q.GetTokenByAccessToken(s.T().Context(),
		sql.NullString{String: refreshed.AccessToken, Valid: true})
	s.ErrorIs(err, sql.ErrNoRows, "the access token no longer resolves")
	s.requireInvalidGrant(client, refreshed.RefreshToken, "a disconnected app cannot refresh")

	// The page shows the success message and no longer lists the app.
	page := s.mustGetPage(browser, testBaseURL+location)
	s.Contains(page, "App disconnected.")
	s.NotContains(page, client.Name)
	s.Contains(page, other.Name)

	// Using the app again asks for consent again.
	q := authorizeQueryFor(client.ClientID, client.RedirectUris[0], "openid profile email", s.mustCreateStateAndCodeVerifier(), nil)
	resp, err := browser.Get(testBaseURL + "/oauth/authorize?" + q)
	s.Require().NoError(err)
	resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	consentURL, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Equal("/oauth/consent", consentURL.Path, "reconnecting must ask for consent again")
}

func (s *OAuthFlowSuite) TestConnectedApps_CannotDisconnectAnotherUsersApp() {
	victim := s.mustCompleteOAuthFlow(s.connectedAppsClientParams("Victim"))
	attacker := s.mustRegisterUser(s.mustGenerateAlphanumericString(10), s.mustGenerateRandomString(16),
		s.mustGenerateAlphanumericString(10)+"@example.com")
	s.server.ResetRateLimits()
	browser := s.mustSignInAs(attacker)

	location := s.postDisconnect(browser, url.Values{"client": {victim.Client.ID.String()}, "confirm": {"yes"}})
	s.Equal("/oauth/connected-apps?error=not_connected", location)

	// Without the confirmation, nothing happens either.
	location = s.postDisconnect(s.mustSignInAs(victim.User), url.Values{"client": {victim.Client.ID.String()}})
	s.Equal("/oauth/connected-apps?error=confirm_required", location)

	// A malformed client reference is just not connected.
	location = s.postDisconnect(browser, url.Values{"client": {"not-a-uuid"}, "confirm": {"yes"}})
	s.Equal("/oauth/connected-apps?error=not_connected", location)

	s.True(s.hasConsent(victim.User, victim.Client), "the victim's consent is untouched")
	row := s.tokenRow(victim.TokenResponse.RefreshToken)
	s.False(row.RevokedAt.Valid, "the victim's token is untouched")
	s.mustRefresh(victim.Client, victim.TokenResponse.RefreshToken)
}

func (s *OAuthFlowSuite) TestConnectedApps_DisconnectRequiresCSRF() {
	flow := s.mustCompleteOAuthFlow(s.connectedAppsClientParams("Csrf"))
	s.server.ResetRateLimits()
	browser := s.mustSignInAs(flow.User)

	resp, err := browser.PostForm(connectedAppsURL+"/disconnect", url.Values{
		"client": {flow.Client.ID.String()}, "confirm": {"yes"},
	})
	s.Require().NoError(err)
	resp.Body.Close()
	s.Equal(http.StatusForbidden, resp.StatusCode)
	s.True(s.hasConsent(flow.User, flow.Client), "a refused POST changes nothing")
}

func (s *OAuthFlowSuite) TestConnectedApps_SignedOutRoundTripThroughLogin() {
	password := s.mustGenerateRandomString(16)
	user := s.mustRegisterUser(s.mustGenerateAlphanumericString(10), password,
		s.mustGenerateAlphanumericString(10)+"@example.com")
	browser := s.newBrowser()

	resp, err := browser.Get(connectedAppsURL)
	s.Require().NoError(err)
	resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	loginLocation := resp.Header.Get("Location")
	s.Equal("/oauth/login?return_to=%2Foauth%2Fconnected-apps", loginLocation)

	loginPage := s.mustGetPage(browser, testBaseURL+loginLocation)
	s.Contains(loginPage, `name="return_to" value="/oauth/connected-apps"`)

	resp, err = csrfPostFormLogin(s.T(), browser, testBaseURL+"/oauth/login", url.Values{
		"username":  {user.Username},
		"password":  {password},
		"return_to": {"/oauth/connected-apps"},
	})
	s.Require().NoError(err)
	resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	s.Equal("/oauth/connected-apps", resp.Header.Get("Location"))

	s.Contains(s.mustGetPage(browser, connectedAppsURL), "Connected Apps")
}

func (s *OAuthFlowSuite) TestConnectedApps_SignedOutRoundTripThroughMFA() {
	password := s.mustGenerateRandomString(16)
	user := s.mustRegisterUser(s.mustGenerateAlphanumericString(10), password,
		s.mustGenerateAlphanumericString(10)+"@example.com")
	key, err := mfa.GenerateSecret(user.Username)
	s.Require().NoError(err)
	secret := mfa.GetSecret(key)
	s.mustEnableMFAForUser(user, secret)
	browser := s.newBrowser()

	resp, err := csrfPostFormLogin(s.T(), browser, testBaseURL+"/oauth/login", url.Values{
		"username":  {user.Username},
		"password":  {password},
		"return_to": {"/oauth/connected-apps"},
	})
	s.Require().NoError(err)
	resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	mfaURL, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Equal("/oauth/mfa", mfaURL.Path)
	s.Equal("/oauth/connected-apps", mfaURL.Query().Get("return_to"), "MFA carries the page onward")

	mfaPage := s.mustGetPage(browser, testBaseURL+mfaURL.RequestURI())
	s.Contains(mfaPage, `name="return_to" value="/oauth/connected-apps"`)

	code, err := generateTOTPCode(secret)
	s.Require().NoError(err)
	resp, err = csrfPostFormLogin(s.T(), browser, testBaseURL+"/oauth/mfa", url.Values{
		"pending_id": {mfaURL.Query().Get("pending")},
		"code":       {code},
		"return_to":  {"/oauth/connected-apps"},
	})
	s.Require().NoError(err)
	resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	s.Equal("/oauth/connected-apps", resp.Header.Get("Location"))
}

// An off-site return_to is ignored: sign-in lands on account settings.
func (s *OAuthFlowSuite) TestLogin_RefusesOffsiteReturnTo() {
	password := s.mustGenerateRandomString(16)
	user := s.mustRegisterUser(s.mustGenerateAlphanumericString(10), password,
		s.mustGenerateAlphanumericString(10)+"@example.com")
	for _, target := range []string{"https://evil.example/", "//evil.example/", `/\evil.example`} {
		resp, err := csrfPostFormLogin(s.T(), s.newBrowser(), testBaseURL+"/oauth/login", url.Values{
			"username":  {user.Username},
			"password":  {password},
			"return_to": {target},
		})
		s.Require().NoError(err)
		resp.Body.Close()
		s.Require().Equal(http.StatusFound, resp.StatusCode)
		s.Equal("/oauth/account-settings", resp.Header.Get("Location"), fmt.Sprintf("return_to %q", target))
	}
}

// A metadata-document client (Claude) is listed as the consent screen named
// it: by the host serving its document, with its own name as a claim and the
// document URL in full, and with the resource's name and scope descriptions.
func (s *OAuthFlowSuite) TestConnectedApps_ListsMetadataDocumentClient() {
	clientID := s.randomCIMDClientID()
	const redirectURI = "https://claude.ai/api/mcp/auth_callback"
	s.cimd.serve(clientID, "Claude", redirectURI)
	resource := s.mustRegisterSensibilityLikeResource()
	browser := s.mustSignIn()
	scv := s.mustCreateStateAndCodeVerifier()

	query := cimdAuthorizeQuery(clientID, redirectURI, "sensibility:read offline_access", scv, resource.Uri)
	s.mustApprove(browser, s.requireConsentRedirect(s.get(browser, testBaseURL+"/oauth/authorize?"+query)))

	page := s.mustGetPage(browser, connectedAppsURL)
	s.Contains(page, ">claude.ai</h2>", "the document's host is the app")
	s.Contains(page, "It calls itself “Claude”")
	s.Contains(page, clientID, "the document URL is shown in full")
	s.Contains(page, "Sensibility Test")
	s.Contains(page, "Read your accounts and balances")
	s.Contains(page, html.EscapeString(scopeDescriptionMap["offline_access"]))
	s.NotContains(page, "Change your accounts and balances", "only granted scopes are listed")
}
