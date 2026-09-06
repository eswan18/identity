//go:build integration

package httpserver

import (
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/eswan18/identity/pkg/db"
	"github.com/google/uuid"
)

// These tests pin the whole invariant end to end, against a real server and
// database: admin scopes are reachable through client_credentials and through
// nothing else.
//
// The unit tests in authorize_params_test.go cover the decision function. These
// cover the thing that actually matters -- that a user driving the
// authorization-code flow against an admin-scoped client cannot come away with
// a token the /admin routes will accept.

// TestAdminScopeUnreachableViaAuthorizationCode is the escalation path this rule
// closes. A *public* client is the dangerous shape: there is no client_secret,
// so the user can redeem the code themselves with only a client_id and their own
// PKCE verifier. identity-cli defaults --confidential to false, so registering
// one takes a single plausible-looking command.
func (s *OAuthFlowSuite) TestAdminScopeUnreachableViaAuthorizationCode() {
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid", "admin:users:write"},
		IsConfidential: false,
		Audience:       "http://localhost:8080",
	})

	username := s.mustGenerateAlphanumericString(10)
	password := s.mustGenerateAlphanumericString(16)
	s.mustRegisterUser(username, password, fmt.Sprintf("%s@example.com", username))
	httpClient := s.mustLoginAsUser(username, password)

	scv := s.mustCreateStateAndCodeVerifier()
	authorizeURL := fmt.Sprintf(
		"http://localhost:8080/oauth/authorize?response_type=code&client_id=%s&redirect_uri=%s"+
			"&scope=%s&state=%s&code_challenge=%s&code_challenge_method=%s",
		url.QueryEscape(client.ClientID),
		url.QueryEscape(client.RedirectUris[0]),
		url.QueryEscape("openid admin:users:write"),
		url.QueryEscape(scv.State),
		url.QueryEscape(scv.CodeChallenge),
		url.QueryEscape(scv.CodeChallengeMethod),
	)

	resp, err := httpClient.Get(authorizeURL)
	s.Require().NoError(err)
	defer resp.Body.Close()

	// Per RFC 6749 §4.1.2.1 the error goes back to the client's redirect_uri,
	// so this is a 302 carrying error parameters rather than a 4xx.
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	location, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)

	s.Require().Equal("invalid_scope", location.Query().Get("error"),
		"authorize must refuse an admin scope; Location was %s", location)
	s.Require().Contains(location.Query().Get("error_description"), "client_credentials")

	// The decisive assertion: no authorization code was handed out, so there is
	// nothing to redeem.
	s.Require().Empty(location.Query().Get("code"),
		"no authorization code may be issued for a request carrying admin scopes")
}

// TestAdminScopeUnreachableViaConsent covers the second code-minting path.
// HandleConsentPost has its own entry point, and a user can POST to it directly
// rather than being redirected there -- which is exactly how it previously
// diverged from authorize.
func (s *OAuthFlowSuite) TestAdminScopeUnreachableViaConsent() {
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid", "admin:users:write"},
		IsConfidential: false,
		Audience:       "http://localhost:8080",
	})

	username := s.mustGenerateAlphanumericString(10)
	password := s.mustGenerateAlphanumericString(16)
	s.mustRegisterUser(username, password, fmt.Sprintf("%s@example.com", username))
	httpClient := s.mustLoginAsUser(username, password)

	scv := s.mustCreateStateAndCodeVerifier()
	resp, err := csrfPostFormLogin(s.T(), httpClient, "http://localhost:8080/oauth/consent", url.Values{
		"decision":              {"allow"},
		"client_id":             {client.ClientID},
		"redirect_uri":          {client.RedirectUris[0]},
		"scope":                 {"openid admin:users:write"},
		"state":                 {scv.State},
		"code_challenge":        {scv.CodeChallenge},
		"code_challenge_method": {scv.CodeChallengeMethod},
		"response_type":         {"code"},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Require().Equal(http.StatusFound, resp.StatusCode)
	location, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)

	s.Require().Equal("invalid_scope", location.Query().Get("error"),
		"consent must refuse an admin scope; Location was %s", location)
	s.Require().Empty(location.Query().Get("code"),
		"no authorization code may be issued for a consent carrying admin scopes")
}

// TestAdminScopeStillReachableViaClientCredentials is the other half: the rule
// must not break the path the admin API is actually meant to be used through.
// Without this, "reject admin scopes everywhere" would pass every other test in
// this file while making the /admin routes unusable.
func (s *OAuthFlowSuite) TestAdminScopeStillReachableViaClientCredentials() {
	clientSecret := s.mustGenerateRandomString(32)
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: clientSecret, Valid: true},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"admin:users:read", "admin:users:write"},
		IsConfidential: true,
		Audience:       "http://localhost:8080",
	})

	token := s.mustGetClientCredentialsToken(client.ClientID, clientSecret, "admin:users:read")
	s.Require().NotEmpty(token)

	req, err := http.NewRequest(http.MethodGet, "http://localhost:8080/admin/users?limit=1", nil)
	s.Require().NoError(err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := s.httpClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Require().Equal(http.StatusOK, resp.StatusCode,
		"client_credentials remains the supported way to reach the admin API")
}

// TestRefreshTokenCarryingAdminScopeRejected covers the belt-and-braces guard.
// No new refresh token can carry an admin scope now that authorize and consent
// refuse them, and client_credentials issues no refresh token at all -- so this
// row is written directly, standing in for a token minted before the rule
// existed. Such a token must not be able to outlive the rule for its 30-day
// lifetime.
func (s *OAuthFlowSuite) TestRefreshTokenCarryingAdminScopeRejected() {
	clientSecret := s.mustGenerateRandomString(32)
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: clientSecret, Valid: true},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid", "admin:users:write"},
		IsConfidential: true,
		Audience:       "http://localhost:8080",
	})

	username := s.mustGenerateAlphanumericString(10)
	password := s.mustGenerateAlphanumericString(16)
	user := s.mustRegisterUser(username, password, fmt.Sprintf("%s@example.com", username))

	legacyRefreshToken := s.mustGenerateRandomString(32)
	_, err := s.datastore.Q.InsertToken(s.T().Context(), db.InsertTokenParams{
		AccessToken:      sql.NullString{String: s.mustGenerateRandomString(16), Valid: true},
		RefreshToken:     sql.NullString{String: legacyRefreshToken, Valid: true},
		UserID:           uuid.NullUUID{UUID: user.ID, Valid: true},
		ClientID:         client.ID,
		Scope:            []string{"openid", "admin:users:write"},
		TokenType:        sql.NullString{String: "Bearer", Valid: true},
		ExpiresAt:        time.Now().Add(time.Hour),
		RefreshExpiresAt: sql.NullTime{Time: time.Now().Add(24 * time.Hour), Valid: true},
	})
	s.Require().NoError(err)

	resp, err := s.httpClient.PostForm("http://localhost:8080/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {legacyRefreshToken},
		"client_id":     {client.ClientID},
		"client_secret": {clientSecret},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Require().Equal(http.StatusBadRequest, resp.StatusCode,
		"a refresh token carrying admin scopes must not mint a new token")

	body := new(strings.Builder)
	_, err = io.Copy(body, resp.Body)
	s.Require().NoError(err)
	s.Require().Contains(body.String(), "invalid_scope")
}
