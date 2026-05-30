//go:build integration

package httpserver

import (
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/eswan18/identity/pkg/auth"
	"github.com/eswan18/identity/pkg/db"
)

func (s *OAuthFlowSuite) TestPasswordResetTokenCannotBeReused() {
	username := s.mustGenerateAlphanumericString(12)
	password := s.mustGenerateRandomString(16)
	user := s.mustRegisterUser(username, password, fmt.Sprintf("%s@example.com", username))

	// Insert a password reset token directly (skips the "forgot password" email flow).
	rawToken, tokenHash, err := generateResetToken()
	s.Require().NoError(err)
	err = s.datastore.Q.CreatePasswordResetToken(s.T().Context(), db.CreatePasswordResetTokenParams{
		UserID:    user.ID,
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	s.Require().NoError(err)

	// auth.ValidatePassword rejects passwords containing the username, so keep them distinct.
	newPassword := "NewS3cure-" + s.mustGenerateRandomString(16)

	// First reset: succeeds and redirects to login.
	resp, err := s.httpClient.PostForm("http://localhost:8080/oauth/reset-password", url.Values{
		"token":            {rawToken},
		"new_password":     {newPassword},
		"confirm_password": {newPassword},
	})
	s.Require().NoError(err)
	s.Require().NoError(resp.Body.Close())
	s.Require().Equal(http.StatusFound, resp.StatusCode, "first reset should redirect to login")

	// Second reset with same token: must be rejected.
	secondPassword := "Another-" + s.mustGenerateRandomString(16)
	resp, err = s.httpClient.PostForm("http://localhost:8080/oauth/reset-password", url.Values{
		"token":            {rawToken},
		"password":         {secondPassword},
		"confirm_password": {secondPassword},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusBadRequest, resp.StatusCode, "replayed reset token must be rejected")

	// Verify the first password still works (i.e. the replay attempt did NOT change it).
	dbUser, err := s.datastore.Q.GetUserByUsername(s.T().Context(), username)
	s.Require().NoError(err)
	firstMatches, err := auth.VerifyPassword(newPassword, dbUser.PasswordHash)
	s.Require().NoError(err)
	s.True(firstMatches, "first reset password should still be valid after replay attempt")
	secondMatches, err := auth.VerifyPassword(secondPassword, dbUser.PasswordHash)
	s.Require().NoError(err)
	s.False(secondMatches, "second reset attempt must not have changed the password")
}

// TestLogoutAcceptsGET verifies that the logout endpoint (advertised as
// end_session_endpoint in OIDC discovery) accepts GET requests per OIDC
// RP-Initiated Logout 1.0, which expects browsers to navigate to it via redirect.
func (s *OAuthFlowSuite) TestPasswordResetFlow() {
	// Register a user
	username := s.mustGenerateRandomString(10)
	emailAddr := username + "@example.com"
	originalPassword := "originalpassword123"
	newPassword := "newpassword456"

	// Create a user directly in the database
	passwordHash, err := auth.HashPassword(originalPassword)
	s.Require().NoError(err)

	user, err := s.datastore.Q.CreateUser(s.T().Context(), db.CreateUserParams{
		Username:     username,
		Email:        emailAddr,
		PasswordHash: passwordHash,
	})
	s.Require().NoError(err)

	// Request password reset
	resp, err := s.httpClient.PostForm("http://localhost:8080/oauth/forgot-password", url.Values{
		"email": {emailAddr},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)

	// Get the token from the database (in real scenario, user would get it from email)
	tokens, err := s.datastore.DB.QueryContext(s.T().Context(),
		"SELECT token_hash FROM auth_email_tokens WHERE user_id = $1 AND token_type = 'password_reset' ORDER BY created_at DESC LIMIT 1",
		user.ID)
	s.Require().NoError(err)
	defer tokens.Close()

	s.True(tokens.Next(), "should have a password reset token")
	var storedHash string
	err = tokens.Scan(&storedHash)
	s.Require().NoError(err)

	// Generate a token that hashes to the stored hash (we need the raw token)
	// Since we can't reverse the hash, we'll create a new token for testing
	rawToken, tokenHash, err := generateResetToken()
	s.Require().NoError(err)

	// Store our test token
	_, err = s.datastore.DB.ExecContext(s.T().Context(),
		"INSERT INTO auth_email_tokens (user_id, token_hash, token_type, expires_at) VALUES ($1, $2, 'password_reset', NOW() + INTERVAL '1 hour')",
		user.ID, tokenHash)
	s.Require().NoError(err)

	// Visit reset password page with token
	resp, err = s.httpClient.Get("http://localhost:8080/oauth/reset-password?token=" + rawToken)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)

	// Submit new password
	resp, err = s.httpClient.PostForm("http://localhost:8080/oauth/reset-password", url.Values{
		"token":            {rawToken},
		"new_password":     {newPassword},
		"confirm_password": {newPassword},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusFound, resp.StatusCode)
	s.Contains(resp.Header.Get("Location"), "/oauth/login?password_reset=true")

	// Verify old password no longer works by trying to login
	// First, create an OAuth client for testing login
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

	// Try login with old password (should fail)
	resp, err = s.httpClient.PostForm("http://localhost:8080/oauth/login", url.Values{
		"username":              {username},
		"password":              {originalPassword},
		"client_id":             {client.ClientID},
		"redirect_uri":          {client.RedirectUris[0]},
		"state":                 {scv.State},
		"scope":                 {"openid"},
		"code_challenge":        {scv.CodeChallenge},
		"code_challenge_method": {scv.CodeChallengeMethod},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusUnauthorized, resp.StatusCode)

	// Try login with new password (should succeed — redirects to authorize)
	resp, err = s.httpClient.PostForm("http://localhost:8080/oauth/login", url.Values{
		"username":              {username},
		"password":              {newPassword},
		"client_id":             {client.ClientID},
		"redirect_uri":          {client.RedirectUris[0]},
		"state":                 {scv.State},
		"scope":                 {"openid"},
		"code_challenge":        {scv.CodeChallenge},
		"code_challenge_method": {scv.CodeChallengeMethod},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusFound, resp.StatusCode)
	s.Contains(resp.Header.Get("Location"), "/oauth/authorize")
}

func (s *OAuthFlowSuite) TestPasswordResetWithInvalidToken() {
	resp, err := s.httpClient.Get("http://localhost:8080/oauth/reset-password?token=invalid-token-123")
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusBadRequest, resp.StatusCode)
}

func (s *OAuthFlowSuite) TestPasswordResetWithMissingToken() {
	resp, err := s.httpClient.Get("http://localhost:8080/oauth/reset-password")
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusBadRequest, resp.StatusCode)
}

func (s *OAuthFlowSuite) TestPasswordResetPasswordMismatch() {
	// Create a valid token
	rawToken, tokenHash, err := generateResetToken()
	s.Require().NoError(err)

	// Create a user and token
	username := s.mustGenerateRandomString(10)
	emailAddr := username + "@example.com"
	passwordHash, err := auth.HashPassword("password123")
	s.Require().NoError(err)

	user, err := s.datastore.Q.CreateUser(s.T().Context(), db.CreateUserParams{
		Username:     username,
		Email:        emailAddr,
		PasswordHash: passwordHash,
	})
	s.Require().NoError(err)

	_, err = s.datastore.DB.ExecContext(s.T().Context(),
		"INSERT INTO auth_email_tokens (user_id, token_hash, token_type, expires_at) VALUES ($1, $2, 'password_reset', NOW() + INTERVAL '1 hour')",
		user.ID, tokenHash)
	s.Require().NoError(err)

	// Submit with mismatched passwords
	resp, err := s.httpClient.PostForm("http://localhost:8080/oauth/reset-password", url.Values{
		"token":            {rawToken},
		"new_password":     {"newpassword123"},
		"confirm_password": {"differentpassword"},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusBadRequest, resp.StatusCode)
}

func (s *OAuthFlowSuite) TestPasswordResetTooShort() {
	// Create a valid token
	rawToken, tokenHash, err := generateResetToken()
	s.Require().NoError(err)

	// Create a user and token
	username := s.mustGenerateRandomString(10)
	emailAddr := username + "@example.com"
	passwordHash, err := auth.HashPassword("password123")
	s.Require().NoError(err)

	user, err := s.datastore.Q.CreateUser(s.T().Context(), db.CreateUserParams{
		Username:     username,
		Email:        emailAddr,
		PasswordHash: passwordHash,
	})
	s.Require().NoError(err)

	_, err = s.datastore.DB.ExecContext(s.T().Context(),
		"INSERT INTO auth_email_tokens (user_id, token_hash, token_type, expires_at) VALUES ($1, $2, 'password_reset', NOW() + INTERVAL '1 hour')",
		user.ID, tokenHash)
	s.Require().NoError(err)

	// Submit with too short password
	resp, err := s.httpClient.PostForm("http://localhost:8080/oauth/reset-password", url.Values{
		"token":            {rawToken},
		"new_password":     {"short"},
		"confirm_password": {"short"},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusBadRequest, resp.StatusCode)
}

func (s *OAuthFlowSuite) TestForgotPasswordNoEmailEnumeration() {
	// Request reset for non-existent email - should return same response as valid email
	resp, err := s.httpClient.PostForm("http://localhost:8080/oauth/forgot-password", url.Values{
		"email": {"nonexistent@example.com"},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()
	// Should return 200 OK with success message (not an error)
	s.Equal(http.StatusOK, resp.StatusCode)
}

func (s *OAuthFlowSuite) TestForgotPasswordGetPage() {
	resp, err := s.httpClient.Get("http://localhost:8080/oauth/forgot-password")
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)
}

// Forgot Username Tests
func (s *OAuthFlowSuite) TestForgotUsernameFlow() {
	// Create a user
	username := s.mustGenerateRandomString(10)
	emailAddr := username + "@example.com"
	passwordHash, err := auth.HashPassword("password123")
	s.Require().NoError(err)

	_, err = s.datastore.Q.CreateUser(s.T().Context(), db.CreateUserParams{
		Username:     username,
		Email:        emailAddr,
		PasswordHash: passwordHash,
	})
	s.Require().NoError(err)

	// Request username reminder
	resp, err := s.httpClient.PostForm("http://localhost:8080/oauth/forgot-username", url.Values{
		"email": {emailAddr},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)

	// Check response contains success message (we can't easily check email was sent)
	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	s.Contains(string(body), "If an account with that email exists")
}

func (s *OAuthFlowSuite) TestForgotUsernameNoEmailEnumeration() {
	// Request reminder for non-existent email - should return same response as valid email
	resp, err := s.httpClient.PostForm("http://localhost:8080/oauth/forgot-username", url.Values{
		"email": {"nonexistent@example.com"},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()
	// Should return 200 OK with success message (not an error)
	s.Equal(http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	s.Contains(string(body), "If an account with that email exists")
}

func (s *OAuthFlowSuite) TestForgotUsernameGetPage() {
	resp, err := s.httpClient.Get("http://localhost:8080/oauth/forgot-username")
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)
}

func (s *OAuthFlowSuite) TestForgotUsernameMissingEmail() {
	resp, err := s.httpClient.PostForm("http://localhost:8080/oauth/forgot-username", url.Values{})
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusBadRequest, resp.StatusCode)
}

// Success Page Tests
func (s *OAuthFlowSuite) TestPasswordResetUpdatesPasswordChangedAt() {
	// Register a user
	username := s.mustGenerateRandomString(8)
	password := s.mustGenerateRandomString(16)
	email := fmt.Sprintf("%s@example.com", s.mustGenerateRandomString(8))
	user := s.mustRegisterUser(username, password, email)

	// Verify password_changed_at is initially NULL
	userBefore, err := s.datastore.Q.GetUserByID(s.T().Context(), user.ID)
	s.Require().NoError(err)
	s.False(userBefore.PasswordChangedAt.Valid, "password_changed_at should be NULL initially")

	// Create a password reset token directly in the database
	rawToken, tokenHash, err := generateResetToken()
	s.Require().NoError(err)

	err = s.datastore.Q.CreatePasswordResetToken(s.T().Context(), db.CreatePasswordResetTokenParams{
		UserID:    user.ID,
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	s.Require().NoError(err)

	// Reset password using the token
	newPassword := s.mustGenerateRandomString(16)
	resp, err := s.httpClient.PostForm("http://localhost:8080/oauth/reset-password", url.Values{
		"token":            {rawToken},
		"new_password":     {newPassword},
		"confirm_password": {newPassword},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode, "password reset should redirect to login")

	// Verify password_changed_at is now set
	userAfter, err := s.datastore.Q.GetUserByID(s.T().Context(), user.ID)
	s.Require().NoError(err)
	s.True(userAfter.PasswordChangedAt.Valid, "password_changed_at should be set after password reset")
	s.WithinDuration(time.Now(), userAfter.PasswordChangedAt.Time, 5*time.Second, "password_changed_at should be recent")
}
