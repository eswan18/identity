//go:build integration

package httpserver

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/eswan18/identity/pkg/db"
)

// A deactivated user must not obtain an authorization code from either
// code-minting path.
//
// The precondition is reachable because deactivation deletes only the session
// that performed it (HandleDeactivateAccountPost calls DeleteSession with the
// request's own cookie, not DeleteAllUserSessions), so a session on another
// device survives. HandleOauthAuthorize has always refused such a user;
// HandleConsentPost never checked, because the is-active check lived inline in
// authorize rather than in the shared validation the two supposedly agreed on.
//
// Both tests deactivate the account directly, standing in for a session that was
// established before deactivation.

func (s *OAuthFlowSuite) mustDeactivatedUserClient() (*http.Client, db.OauthClient, StateAndCodeVerifier) {
	s.T().Helper()
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid", "profile", "email"},
		IsConfidential: false,
		Audience:       "http://localhost:8080",
	})

	username := s.mustGenerateAlphanumericString(10)
	password := s.mustGenerateAlphanumericString(16)
	user := s.mustRegisterUser(username, password, fmt.Sprintf("%s@example.com", username))

	// Log in first, then deactivate: the session outlives the deactivation, which
	// is what makes this reachable at all.
	httpClient := s.mustLoginAsUser(username, password)
	s.Require().NoError(s.datastore.Q.DeactivateUser(s.T().Context(), user.ID))

	return httpClient, client, s.mustCreateStateAndCodeVerifier()
}

// TestDeactivatedUserGetsNoCodeFromAuthorize is the regression half: authorize
// already behaved correctly and must keep doing so now the check has moved into
// checkCodeIssuance.
func (s *OAuthFlowSuite) TestDeactivatedUserGetsNoCodeFromAuthorize() {
	httpClient, client, scv := s.mustDeactivatedUserClient()

	authorizeURL := fmt.Sprintf(
		"http://localhost:8080/oauth/authorize?response_type=code&client_id=%s&redirect_uri=%s"+
			"&scope=%s&state=%s&code_challenge=%s&code_challenge_method=%s",
		url.QueryEscape(client.ClientID),
		url.QueryEscape(client.RedirectUris[0]),
		url.QueryEscape("openid"),
		url.QueryEscape(scv.State),
		url.QueryEscape(scv.CodeChallenge),
		url.QueryEscape(scv.CodeChallengeMethod),
	)

	resp, err := httpClient.Get(authorizeURL)
	s.Require().NoError(err)
	defer resp.Body.Close()

	location, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Require().Empty(location.Query().Get("code"),
		"a deactivated user must not receive an authorization code")
	s.Require().Contains(resp.Header.Get("Location"), "account_deactivated")
}

// TestDeactivatedUserGetsNoCodeFromConsent is the bug this change fixes.
// Before it, this POST returned a 302 to the client's redirect_uri carrying a
// usable-looking authorization code.
func (s *OAuthFlowSuite) TestDeactivatedUserGetsNoCodeFromConsent() {
	httpClient, client, scv := s.mustDeactivatedUserClient()

	resp, err := csrfPostFormLogin(s.T(), httpClient, "http://localhost:8080/oauth/consent", url.Values{
		"decision":              {"allow"},
		"client_id":             {client.ClientID},
		"redirect_uri":          {client.RedirectUris[0]},
		"scope":                 {"openid"},
		"state":                 {scv.State},
		"code_challenge":        {scv.CodeChallenge},
		"code_challenge_method": {scv.CodeChallengeMethod},
		"response_type":         {"code"},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()

	location, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Require().Empty(location.Query().Get("code"),
		"a deactivated user must not receive an authorization code from the consent endpoint either")
	s.Require().Contains(resp.Header.Get("Location"), "account_deactivated")
}

// TestDeactivatedUserDenyingConsentStillTellsTheClient covers an ordering trap.
//
// When the precondition check ran before the decision was read, a deactivated
// user clicking "Deny" was redirected to the login page and the client was left
// waiting, never learning the user had refused. Declining consent mints no code,
// so the preconditions for minting one must not gate it.
func (s *OAuthFlowSuite) TestDeactivatedUserDenyingConsentStillTellsTheClient() {
	httpClient, client, scv := s.mustDeactivatedUserClient()

	resp, err := csrfPostFormLogin(s.T(), httpClient, "http://localhost:8080/oauth/consent", url.Values{
		"decision":              {"deny"},
		"client_id":             {client.ClientID},
		"redirect_uri":          {client.RedirectUris[0]},
		"scope":                 {"openid"},
		"state":                 {scv.State},
		"code_challenge":        {scv.CodeChallenge},
		"code_challenge_method": {scv.CodeChallengeMethod},
		"response_type":         {"code"},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()

	location, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Require().Equal("access_denied", location.Query().Get("error"),
		"the client must learn the user refused, whatever the state of their account; got %s",
		resp.Header.Get("Location"))
	s.Require().Empty(location.Query().Get("code"))
}

// TestDeactivatedConsentRedirectKeepsOAuthContext pins that a user bounced from
// the consent endpoint can get back to the app. Dropping the parameters here
// strands them on the account page after reactivating, while the same user
// bounced from /oauth/authorize resumes correctly -- an inconsistency between
// the two paths of exactly the kind this seam exists to prevent.
func (s *OAuthFlowSuite) TestDeactivatedConsentRedirectKeepsOAuthContext() {
	httpClient, client, scv := s.mustDeactivatedUserClient()

	resp, err := csrfPostFormLogin(s.T(), httpClient, "http://localhost:8080/oauth/consent", url.Values{
		"decision":              {"allow"},
		"client_id":             {client.ClientID},
		"redirect_uri":          {client.RedirectUris[0]},
		"scope":                 {"openid"},
		"state":                 {scv.State},
		"code_challenge":        {scv.CodeChallenge},
		"code_challenge_method": {scv.CodeChallengeMethod},
		"response_type":         {"code"},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()

	location, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Require().Equal("account_deactivated", location.Query().Get("error"))
	s.Require().Equal(client.ClientID, location.Query().Get("client_id"),
		"the OAuth context must survive the bounce; got %s", resp.Header.Get("Location"))
	s.Require().Equal(scv.State, location.Query().Get("state"))
}

// TestConsentGetRefusesDeactivatedUser: the form is not rendered to a user whose
// submit would be refused.
func (s *OAuthFlowSuite) TestConsentGetRefusesDeactivatedUser() {
	httpClient, client, scv := s.mustDeactivatedUserClient()

	consentURL := fmt.Sprintf(
		"http://localhost:8080/oauth/consent?response_type=code&client_id=%s&redirect_uri=%s"+
			"&scope=%s&state=%s&code_challenge=%s&code_challenge_method=%s",
		url.QueryEscape(client.ClientID),
		url.QueryEscape(client.RedirectUris[0]),
		url.QueryEscape("openid"),
		url.QueryEscape(scv.State),
		url.QueryEscape(scv.CodeChallenge),
		url.QueryEscape(scv.CodeChallengeMethod),
	)
	resp, err := httpClient.Get(consentURL)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Require().Equal(http.StatusFound, resp.StatusCode,
		"a deactivated user should be redirected, not shown a consent form")
	s.Require().Contains(resp.Header.Get("Location"), "account_deactivated")
}
