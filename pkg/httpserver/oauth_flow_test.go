//go:build integration

package httpserver

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"

	"github.com/eswan18/identity/pkg/db"
)

func (s *OAuthFlowSuite) TestFullOAuthFlow() {
	clientCallbackURI := "http://localhost:8080/callback"
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: "", Valid: false},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{clientCallbackURI},
		AllowedScopes:  []string{"openid", "profile", "email"},
		IsConfidential: false,
		Audience:       "http://localhost:8000",
	})
	user := s.mustRegisterUser(
		s.mustGenerateRandomString(8),
		s.mustGenerateRandomString(8),
		fmt.Sprintf("%s@example.com", s.mustGenerateRandomString(8)),
	)
	scv := s.mustCreateStateAndCodeVerifier()

	s.Run("/oauth/authorize", func() {
		// Calling authorize should redirect to the login page with the OAuth parameters preserved.

		// Call /authorize
		host := "localhost:8080"
		route := "/oauth/authorize"
		query := url.Values{
			"client_id":             {client.ClientID},
			"redirect_uri":          {clientCallbackURI},
			"response_type":         {"code"},
			"code_challenge":        {scv.CodeChallenge},
			"code_challenge_method": {scv.CodeChallengeMethod},
			"state":                 {scv.State},
			"scope":                 {"openid profile email"},
		}
		authorizeUrl := fmt.Sprintf("http://%s%s?%s", host, route, query.Encode())
		resp, err := s.httpClient.Get(authorizeUrl)
		s.Require().NoError(err)
		defer resp.Body.Close()
		s.Equal(http.StatusFound, resp.StatusCode)
		// Verify it redirects to the login page
		location := resp.Header.Get("Location")
		redirectUrl, err := url.ParseRequestURI(location)
		s.Require().NoError(err)
		// We should be redirected to the login page with the OAuth parameters preserved.
		s.Equal("/oauth/login", redirectUrl.Path)
		s.Equal(query, redirectUrl.Query())
	})

	// Create a variable to store the returned authorization code, which we'll use later.
	var authorizationCode string
	s.Run("/oauth/login", func() {
		// Login + consent flow: login → authorize → consent → approve → callback with code
		authorizationCode = s.mustLoginAndConsent(user, client.ClientID, clientCallbackURI, "openid profile email", scv)
		s.NotEmpty(authorizationCode)
	})

	// Create a variable to store the returned token response, which we'll use later.
	var tokenResponse TokenResponse
	s.Run("/oauth/token", func() {
		// Calling token should exchange the authorization code for a token.

		// Call /token
		host := "localhost:8080"
		route := "/oauth/token"
		tokenQuery := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {authorizationCode},
			"redirect_uri":  {clientCallbackURI},
			"client_id":     {client.ClientID},
			"code_verifier": {scv.CodeVerifier},
		}
		postTokenUrl := fmt.Sprintf("http://%s%s", host, route)
		resp, err := s.httpClient.PostForm(postTokenUrl, tokenQuery)
		s.Require().NoError(err)
		defer resp.Body.Close()
		if !s.Equal(http.StatusOK, resp.StatusCode) {
			body, err := io.ReadAll(resp.Body)
			s.Require().NoError(err)
			s.T().Logf("response body: %s", string(body))
			s.FailNow("unexpected status code found")
		}
		body, err := io.ReadAll(resp.Body)
		s.Require().NoError(err)
		err = json.Unmarshal(body, &tokenResponse)
		s.Require().NoError(err)
		s.NotEmpty(tokenResponse.AccessToken)
		s.Equal("Bearer", tokenResponse.TokenType)
		s.Greater(tokenResponse.ExpiresIn, 0)
		s.NotEmpty(tokenResponse.RefreshToken)
		s.Equal("openid profile email", tokenResponse.Scope)
	})

	s.Run("/oauth/refresh", func() {
		// Calling refresh should exchange the refresh token for a new token.

		// Call /refresh
		host := "localhost:8080"
		route := "/oauth/refresh"
		refreshQuery := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {tokenResponse.RefreshToken},
			"client_id":     {client.ClientID},
		}
		postRefreshUrl := fmt.Sprintf("http://%s%s", host, route)
		resp, err := s.httpClient.PostForm(postRefreshUrl, refreshQuery)
		s.Require().NoError(err)
		defer resp.Body.Close()
		s.Equal(http.StatusOK, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		s.Require().NoError(err)
		err = json.Unmarshal(body, &tokenResponse)
		s.Require().NoError(err)
		s.NotEmpty(tokenResponse.AccessToken)
		s.Equal("Bearer", tokenResponse.TokenType)
		s.Greater(tokenResponse.ExpiresIn, 0)
		s.NotEmpty(tokenResponse.RefreshToken)
		s.Equal("openid profile email", tokenResponse.Scope)
	})
}

// TestAuthorizationCodeCannotBeReused verifies that an authorization code is
// single-use: the first token exchange succeeds, the second with the same code
// is rejected with invalid_grant. Guards against the TOCTOU where two concurrent
// token requests could both consume the same code.
func (s *OAuthFlowSuite) TestAuthorizationCodeCannotBeReused() {
	clientCallbackURI := "http://localhost:8080/callback"
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: "", Valid: false},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{clientCallbackURI},
		AllowedScopes:  []string{"openid", "profile", "email"},
		IsConfidential: false,
		Audience:       "http://localhost:8080",
	})
	user := s.mustRegisterUser(
		s.mustGenerateAlphanumericString(12),
		s.mustGenerateRandomString(16),
		fmt.Sprintf("%s@example.com", s.mustGenerateAlphanumericString(8)),
	)
	scv := s.mustCreateStateAndCodeVerifier()

	code := s.mustLoginAndConsent(user, client.ClientID, clientCallbackURI, "openid profile email", scv)

	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {clientCallbackURI},
		"client_id":     {client.ClientID},
		"code_verifier": {scv.CodeVerifier},
	}

	// First exchange: succeeds.
	resp, err := s.httpClient.PostForm("http://localhost:8080/oauth/token", tokenForm)
	s.Require().NoError(err)
	s.Require().NoError(resp.Body.Close())
	s.Require().Equal(http.StatusOK, resp.StatusCode, "first code exchange should succeed")

	// Second exchange with the same code: must be rejected.
	resp, err = s.httpClient.PostForm("http://localhost:8080/oauth/token", tokenForm)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusBadRequest, resp.StatusCode, "replayed code must be rejected")

	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	var errResp map[string]string
	s.Require().NoError(json.Unmarshal(body, &errResp))
	s.Equal("invalid_grant", errResp["error"], "replay should return invalid_grant")
}

// TestLoginFailedPreservesAllScopes verifies that when login fails due to
// invalid credentials, all OAuth scope parameters are preserved in the
// re-rendered login form (not just the first scope).
func (s *OAuthFlowSuite) TestLoginFailedPreservesAllScopes() {
	// Create a user
	username := s.mustGenerateRandomString(8)
	password := s.mustGenerateRandomString(16)
	email := fmt.Sprintf("%s@example.com", username)
	s.mustRegisterUser(username, password, email)

	// Create an OAuth client with multiple scopes
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: "", Valid: false},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid", "profile", "email"},
		IsConfidential: false,
		Audience:       "https://api.example.com",
	})
	scv := s.mustCreateStateAndCodeVerifier()

	// POST to login with WRONG password and multiple scopes
	resp, err := s.httpClient.PostForm("http://localhost:8080/oauth/login", url.Values{
		"username":              {username},
		"password":              {"wrong-password"},
		"client_id":             {client.ClientID},
		"redirect_uri":          {client.RedirectUris[0]},
		"state":                 {scv.State},
		"scope":                 {"openid profile email"}, // space-separated scopes
		"code_challenge":        {scv.CodeChallenge},
		"code_challenge_method": {scv.CodeChallengeMethod},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()

	// Should return 401 Unauthorized
	s.Equal(http.StatusUnauthorized, resp.StatusCode)

	// Read the response body (the re-rendered login form)
	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	bodyStr := string(body)

	// Verify ALL scopes are preserved in the hidden input field
	// The template should render: value="openid profile email"
	s.Contains(bodyStr, `name="scope"`, "response should contain scope hidden input")
	s.Contains(bodyStr, "openid", "response should contain openid scope")
	s.Contains(bodyStr, "profile", "response should contain profile scope")
	s.Contains(bodyStr, "email", "response should contain email scope")

	// More specifically, check that the scopes appear together in the value attribute
	// This ensures they're in a single input, not split across multiple
	s.Contains(bodyStr, `value="openid profile email"`, "all scopes should be in a single hidden input value")
}

// TestLoginSetsLastLoginAt verifies that successful login updates the last_login_at timestamp.
func (s *OAuthFlowSuite) TestLoginSetsLastLoginAt() {
	// Register a user
	username := s.mustGenerateRandomString(8)
	password := s.mustGenerateRandomString(16)
	email := fmt.Sprintf("%s@example.com", s.mustGenerateRandomString(8))
	user := s.mustRegisterUser(username, password, email)

	// Verify last_login_at is initially NULL
	userBefore, err := s.datastore.Q.GetUserByID(s.T().Context(), user.ID)
	s.Require().NoError(err)
	s.False(userBefore.LastLoginAt.Valid, "last_login_at should be NULL before first login")

	// Create an OAuth client and complete login
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: "", Valid: false},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid"},
		IsConfidential: false,
		Audience:       "https://api.example.com",
	})
	scv := s.mustCreateStateAndCodeVerifier()

	// Login
	resp, err := s.httpClient.PostForm("http://localhost:8080/oauth/login", url.Values{
		"username":              {username},
		"password":              {password},
		"client_id":             {client.ClientID},
		"redirect_uri":          {client.RedirectUris[0]},
		"state":                 {scv.State},
		"scope":                 {"openid"},
		"code_challenge":        {scv.CodeChallenge},
		"code_challenge_method": {scv.CodeChallengeMethod},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode, "login should succeed with redirect")

	// Verify last_login_at is now set
	userAfter, err := s.datastore.Q.GetUserByID(s.T().Context(), user.ID)
	s.Require().NoError(err)
	s.True(userAfter.LastLoginAt.Valid, "last_login_at should be set after login")
	s.WithinDuration(time.Now(), userAfter.LastLoginAt.Time, 5*time.Second, "last_login_at should be recent")
}

// TestPasswordChangeUpdatesPasswordChangedAt verifies that changing password updates password_changed_at.
func (s *OAuthFlowSuite) TestPasswordChangeUpdatesPasswordChangedAt() {
	// Register a user
	username := s.mustGenerateRandomString(8)
	password := s.mustGenerateRandomString(16)
	email := fmt.Sprintf("%s@example.com", s.mustGenerateRandomString(8))
	user := s.mustRegisterUser(username, password, email)

	// Verify password_changed_at is initially NULL
	userBefore, err := s.datastore.Q.GetUserByID(s.T().Context(), user.ID)
	s.Require().NoError(err)
	s.False(userBefore.PasswordChangedAt.Valid, "password_changed_at should be NULL initially")

	// Create an HTTP client with cookie jar to maintain session
	jar, err := cookiejar.New(nil)
	s.Require().NoError(err)
	httpClientWithCookies := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Do a direct login (no client_id) to get a session
	resp, err := httpClientWithCookies.PostForm("http://localhost:8080/oauth/login", url.Values{
		"username": {username},
		"password": {password},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode, "direct login should redirect to account settings")

	// Change password
	newPassword := s.mustGenerateRandomString(16)
	resp, err = httpClientWithCookies.PostForm("http://localhost:8080/oauth/change-password", url.Values{
		"current_password": {password},
		"new_password":     {newPassword},
		"confirm_password": {newPassword},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()
	// A successful password change logs the user out everywhere: it redirects
	// to the login page rather than rendering the change-password page inline.
	s.Require().Equal(http.StatusFound, resp.StatusCode, "password change should redirect to login")
	s.Require().Equal("/oauth/login?password_changed=true", resp.Header.Get("Location"))

	// Verify password_changed_at is now set
	userAfter, err := s.datastore.Q.GetUserByID(s.T().Context(), user.ID)
	s.Require().NoError(err)
	s.True(userAfter.PasswordChangedAt.Valid, "password_changed_at should be set after password change")
	s.WithinDuration(time.Now(), userAfter.PasswordChangedAt.Time, 5*time.Second, "password_changed_at should be recent")

	// The session used to change the password should have been invalidated,
	// since a password change revokes all sessions for the user.
	var sessionCookieValue string
	for _, c := range jar.Cookies(&url.URL{Scheme: "http", Host: "localhost:8080"}) {
		if c.Name == "session_id" {
			sessionCookieValue = c.Value
		}
	}
	s.Empty(sessionCookieValue, "session cookie should be cleared after password change")
}
