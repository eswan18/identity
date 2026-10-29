//go:build integration

package httpserver

import (
	"database/sql"
	"net/http"
	"net/url"

	"github.com/eswan18/identity/pkg/db"
)

// Grants the Connected Apps page must account for beyond consent rows, and the
// race between a disconnect and a code exchange.

// deleteConsents removes user's consents for client behind the server's back,
// leaving its tokens: the state an older release's redirect-URI change left.
func (s *OAuthFlowSuite) deleteConsents(user UserWithPassword, client db.OauthClient) {
	s.T().Helper()
	_, err := s.datastore.Q.DeleteUserConsentsForUserClient(s.T().Context(), db.DeleteUserConsentsForUserClientParams{
		UserID: user.ID, ClientID: client.ID,
	})
	s.Require().NoError(err)
}

// An app holding a live token with no consent behind it is still listed, with
// what its tokens can access, and disconnecting it revokes them.
func (s *OAuthFlowSuite) TestConnectedApps_ListsAndDisconnectsAppWithTokensButNoConsent() {
	flow := s.mustCompleteOAuthFlow(s.connectedAppsClientParams("Token Only"))
	s.server.ResetRateLimits()
	s.deleteConsents(flow.User, flow.Client)
	s.Require().False(s.hasConsent(flow.User, flow.Client))

	browser := s.mustSignInAs(flow.User)
	page := s.mustGetPage(browser, connectedAppsURL)
	s.Contains(page, flow.Client.Name, "an app with a live token is listed without a consent")
	s.Contains(page, "connected-apps.example", "the resource its tokens are for is named")
	s.Contains(page, "Verify your identity", "its tokens' scopes are described")
	s.NotContains(page, "No apps are connected")

	location := s.postDisconnect(browser, url.Values{"client": {flow.Client.ID.String()}, "confirm": {"yes"}})
	s.Equal("/oauth/connected-apps?success=disconnected", location)
	row := s.tokenRow(flow.TokenResponse.RefreshToken)
	s.True(row.RevokedAt.Valid, "disconnect revokes the token though there was no consent")
	s.Equal("user_disconnected", row.RevokedReason.String)
	s.requireInvalidGrant(flow.Client, flow.TokenResponse.RefreshToken, "no refresh after disconnecting")

	page = s.mustGetPage(browser, testBaseURL+location)
	s.NotContains(page, flow.Client.Name, "gone once its tokens are revoked")
	s.Contains(page, "anything it already holds expires within an hour",
		"the page does not promise more than revocation can deliver")
}

// Dead tokens (revoked, or with both halves expired) do not make an app
// connected; and a trusted client is not listed for its tokens either.
func (s *OAuthFlowSuite) TestConnectedApps_IgnoresDeadTokensAndTrustedClients() {
	expired := s.mustCompleteOAuthFlow(s.connectedAppsClientParams("Expired"))
	s.server.ResetRateLimits()
	s.deleteConsents(expired.User, expired.Client)
	_, err := s.datastore.DB.ExecContext(s.T().Context(),
		`UPDATE oauth_tokens SET expires_at = now() - interval '1 hour', refresh_expires_at = now() - interval '1 hour'
		 WHERE user_id = $1 AND client_id = $2`, expired.User.ID, expired.Client.ID)
	s.Require().NoError(err)
	page := s.mustGetPage(s.mustSignInAs(expired.User), connectedAppsURL)
	s.NotContains(page, expired.Client.Name, "an expired token does not connect an app")

	trusted := s.mustCompleteOAuthFlow(s.connectedAppsClientParams("Trusted Tokens"))
	s.server.ResetRateLimits()
	_, err = s.datastore.Q.UpdateOAuthClient(s.T().Context(), db.UpdateOAuthClientParams{
		ClientID: trusted.Client.ClientID, Trusted: sql.NullBool{Bool: true, Valid: true},
	})
	s.Require().NoError(err)
	s.deleteConsents(trusted.User, trusted.Client)
	page = s.mustGetPage(s.mustSignInAs(trusted.User), connectedAppsURL)
	s.NotContains(page, trusted.Client.Name, "a trusted client is not listed for its tokens")
}

// A disconnect between authorize issuing a code and the client exchanging it
// leaves the client with nothing: the exchange is refused and no token is
// stored. A trusted client, which has no consent, exchanges as usual.
func (s *OAuthFlowSuite) TestCodeExchange_RefusedAfterConsentWithdrawn() {
	client := s.mustRegisterOAuthClient(s.connectedAppsClientParams("Raced"))
	user := s.newTestUser()
	scv := s.mustCreateStateAndCodeVerifier()
	code := s.mustLoginAndConsent(user, client.ClientID, client.RedirectUris[0], "openid", scv)
	s.server.ResetRateLimits()

	// The code is already out when the user disconnects. (A disconnect also
	// deletes unexchanged codes; deleting only the consent is the window
	// after the code was consumed and before the tokens were stored.)
	s.deleteConsents(user, client)

	status, body := s.postTokenForm(exchangeForm(client, code, scv, nil))
	s.Equal(http.StatusBadRequest, status)
	s.Equal("invalid_grant", body["error"])
	var n int
	s.Require().NoError(s.datastore.DB.QueryRowContext(s.T().Context(),
		`SELECT count(*) FROM oauth_tokens WHERE user_id = $1 AND client_id = $2`, user.ID, client.ID).Scan(&n))
	s.Zero(n, "no token is stored without a consent")

	// The consent present: the same exchange succeeds (covered by every flow
	// test), and for a trusted client no consent is needed at all.
	trusted := s.mustRegisterOAuthClient(s.trustedClientParams("Raced Trusted"))
	browser := s.mustSignInAs(user)
	scv = s.mustCreateStateAndCodeVerifier()
	code = s.requireCode(s.get(browser, testBaseURL+"/oauth/authorize?"+
		authorizeQueryFor(trusted.ClientID, trusted.RedirectUris[0], "openid", scv, nil)))
	status, body = s.postTokenForm(exchangeForm(trusted, code, scv, nil))
	s.Equal(http.StatusOK, status, "%v", body)
}

// A deactivated user who signs in on their way to an active-only page lands on
// account settings (where they can reactivate), not back at login.
func (s *OAuthFlowSuite) TestDeactivatedSignInToActiveOnlyPageLandsOnAccountSettings() {
	user := s.newTestUser()
	s.Require().NoError(s.datastore.Q.DeactivateUser(s.T().Context(), user.ID))
	browser := s.newBrowser()

	resp, err := csrfPostFormLogin(s.T(), browser, testBaseURL+"/oauth/login", url.Values{
		"username": {user.Username}, "password": {user.Password}, "return_to": {"/oauth/change-password"},
	})
	s.Require().NoError(err)
	resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	s.Require().Equal("/oauth/change-password", resp.Header.Get("Location"))

	resp = s.get(browser, testBaseURL+"/oauth/change-password")
	resp.Body.Close()
	s.Equal(http.StatusFound, resp.StatusCode)
	s.Equal("/oauth/account-settings", resp.Header.Get("Location"), "not back to login")
	s.Contains(s.mustGetPage(browser, testBaseURL+"/oauth/account-settings"), "Reactivate")
}
