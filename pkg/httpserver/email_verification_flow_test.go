//go:build integration

package httpserver

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/eswan18/identity/pkg/db"
)

func (s *OAuthFlowSuite) TestEmailVerificationFlow() {
	// Create a client and register a new user
	clientCallbackURI := "http://localhost:8080/callback"
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: "", Valid: false},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{clientCallbackURI},
		AllowedScopes:  []string{"openid", "profile", "email"},
		IsConfidential: false,
		Audience:       "https://api.example.com",
	})
	scv := s.mustCreateStateAndCodeVerifier()

	// Register a new user
	username := s.mustGenerateRandomString(10)
	emailAddr := username + "@example.com"
	password := "securepassword123"

	regResp, err := csrfPostFormLogin(s.T(), s.httpClient, "http://localhost:8080/oauth/register", url.Values{
		"username":              {username},
		"email":                 {emailAddr},
		"password":              {password},
		"confirm_password":      {password},
		"client_id":             {client.ClientID},
		"redirect_uri":          {client.RedirectUris[0]},
		"state":                 {scv.State},
		"scope":                 {"openid profile email"},
		"code_challenge":        {scv.CodeChallenge},
		"code_challenge_method": {scv.CodeChallengeMethod},
	})
	s.Require().NoError(err)
	defer regResp.Body.Close()
	s.Require().Equal(http.StatusFound, regResp.StatusCode)

	// Verify user was created with email_verified = false
	user, err := s.datastore.Q.GetUserByUsername(s.T().Context(), username)
	s.Require().NoError(err)
	s.False(user.EmailVerified, "new user should have email_verified=false")

	// Verify a verification token was created
	// (We can't easily test the email was sent since we use LogSender in tests,
	// but we can verify the token exists in the database)
	// Note: The token is hashed, so we can't look it up directly without the raw token
}

func (s *OAuthFlowSuite) TestEmailVerifiedClaimInJWT() {
	// Complete OAuth flow and check that email_verified claim is in the token
	clientCallbackURI := "http://localhost:8080/callback"
	result := s.mustCompleteOAuthFlow(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: "", Valid: false},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{clientCallbackURI},
		AllowedScopes:  []string{"openid", "profile", "email"},
		IsConfidential: false,
		Audience:       "https://api.example.com",
	})

	// Parse the access token to verify email_verified claim
	parts := strings.Split(result.TokenResponse.AccessToken, ".")
	s.Require().Len(parts, 3, "JWT should have 3 parts")

	// Decode the payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	s.Require().NoError(err)

	var claims map[string]interface{}
	err = json.Unmarshal(payload, &claims)
	s.Require().NoError(err)

	// Check email_verified claim exists and is false (new users aren't verified)
	emailVerified, ok := claims["email_verified"]
	s.True(ok, "JWT should contain email_verified claim")
	s.False(emailVerified.(bool), "email_verified should be false for new user")
}

func (s *OAuthFlowSuite) TestVerifyEmailWithInvalidToken() {
	// Try to verify with an invalid token
	resp, err := s.httpClient.Get("http://localhost:8080/oauth/verify-email?token=invalid-token-123")
	s.Require().NoError(err)
	defer resp.Body.Close()

	// Should show error page (200 with error content, not redirect)
	s.Equal(http.StatusBadRequest, resp.StatusCode)
}

func (s *OAuthFlowSuite) TestVerifyEmailWithMissingToken() {
	// Try to verify without a token
	resp, err := s.httpClient.Get("http://localhost:8080/oauth/verify-email")
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusBadRequest, resp.StatusCode)
}

func (s *OAuthFlowSuite) TestResendVerificationRequiresAuth() {
	// Try to resend verification without being logged in (CSRF-aware POST). With a
	// valid CSRF token but no session, the handler still redirects to login.
	resp, err := csrfPostFormLogin(s.T(), s.httpClient, "http://localhost:8080/oauth/resend-verification", nil)
	s.Require().NoError(err)
	defer resp.Body.Close()

	// Should redirect to login
	s.Equal(http.StatusFound, resp.StatusCode)
	location := resp.Header.Get("Location")
	s.Contains(location, "/oauth/login")
}
