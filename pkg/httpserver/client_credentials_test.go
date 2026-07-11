//go:build integration

package httpserver

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/eswan18/identity/pkg/db"
	"github.com/golang-jwt/jwt/v5"
)

// TestClientCredentialsGrant tests the full client credentials flow
func (s *OAuthFlowSuite) TestClientCredentialsGrant() {
	// Create a confidential client with admin scopes
	clientSecret := s.mustGenerateRandomString(32)
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: clientSecret, Valid: true},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"admin:users:write", "admin:users:read"},
		IsConfidential: true,
		Audience:       "http://localhost:8080",
	})

	// Request token using client credentials
	tokenValues := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {client.ClientID},
		"client_secret": {clientSecret},
		"scope":         {"admin:users:write"},
	}
	resp, err := s.httpClient.PostForm("http://localhost:8080/oauth/token", tokenValues)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	var tokenResponse TokenResponse
	err = json.Unmarshal(body, &tokenResponse)
	s.Require().NoError(err)

	// Verify response structure
	s.NotEmpty(tokenResponse.AccessToken, "should have access token")
	s.Empty(tokenResponse.RefreshToken, "client credentials should not return refresh token")
	s.Equal("Bearer", tokenResponse.TokenType)
	s.Equal(900, tokenResponse.ExpiresIn) // 15 minutes = 900 seconds

	// Parse and verify JWT claims
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(tokenResponse.AccessToken, jwt.MapClaims{})
	s.Require().NoError(err)

	claims := token.Claims.(jwt.MapClaims)
	s.Equal(client.ClientID, claims["sub"], "subject should be client_id")
	s.Equal("http://localhost:8080", claims["iss"], "issuer should match")
	s.Equal("http://localhost:8080", claims["aud"], "audience should match client's audience")
	s.Equal("admin:users:write", claims["scope"], "scope should match requested scope")

	// Verify no user-specific claims
	s.Nil(claims["username"], "should not have username claim")
	s.Nil(claims["email"], "should not have email claim")
	s.Nil(claims["email_verified"], "should not have email_verified claim")
}

// TestClientCredentialsGrant_BasicAuth verifies that client_secret_basic (HTTP Basic Auth)
// works for client authentication at the token endpoint.
func (s *OAuthFlowSuite) TestClientCredentialsGrant_BasicAuth() {
	clientSecret := s.mustGenerateRandomString(32)
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: clientSecret, Valid: true},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"admin:users:read"},
		IsConfidential: true,
		Audience:       "http://localhost:8080",
	})

	// Use Basic auth instead of form values for client credentials
	form := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"admin:users:read"},
	}
	req, err := http.NewRequest("POST", "http://localhost:8080/oauth/token",
		strings.NewReader(form.Encode()))
	s.Require().NoError(err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.ClientID, clientSecret)

	resp, err := s.httpClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	var tokenResponse TokenResponse
	err = json.Unmarshal(body, &tokenResponse)
	s.Require().NoError(err)

	s.NotEmpty(tokenResponse.AccessToken, "should have access token")
	s.Equal("Bearer", tokenResponse.TokenType)
}

// TestClientCredentialsGrant_BasicAuth_WrongSecret verifies that Basic auth
// with a wrong secret is rejected.
func (s *OAuthFlowSuite) TestClientCredentialsGrant_BasicAuth_WrongSecret() {
	clientSecret := s.mustGenerateRandomString(32)
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: clientSecret, Valid: true},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"admin:users:read"},
		IsConfidential: true,
		Audience:       "http://localhost:8080",
	})

	form := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"admin:users:read"},
	}
	req, err := http.NewRequest("POST", "http://localhost:8080/oauth/token",
		strings.NewReader(form.Encode()))
	s.Require().NoError(err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.ClientID, "wrong-secret")

	resp, err := s.httpClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	// Per RFC 6749 §5.2, a failed client authentication at the token endpoint
	// must be reported as 401 (with a WWW-Authenticate challenge), not 400.
	s.Equal(http.StatusUnauthorized, resp.StatusCode)
	s.Equal(`Basic realm="oauth"`, resp.Header.Get("WWW-Authenticate"))

	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	var errorResponse map[string]string
	err = json.Unmarshal(body, &errorResponse)
	s.Require().NoError(err)
	s.Equal("invalid_client", errorResponse["error"])
}

// TestClientCredentialsGrant_PublicClientRejected verifies public clients cannot use client credentials
func (s *OAuthFlowSuite) TestClientCredentialsGrant_PublicClientRejected() {
	// Create a public client (no secret)
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: "", Valid: false},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid", "profile"},
		IsConfidential: false,
		Audience:       "http://localhost:8000",
	})

	// Try to use client credentials grant with public client
	tokenValues := url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {client.ClientID},
		"scope":      {"openid"},
	}
	resp, err := s.httpClient.PostForm("http://localhost:8080/oauth/token", tokenValues)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusBadRequest, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	var errorResponse map[string]string
	err = json.Unmarshal(body, &errorResponse)
	s.Require().NoError(err)
	s.Equal("unauthorized_client", errorResponse["error"])
	s.Contains(errorResponse["error_description"], "confidential client")
}

// TestClientCredentialsGrant_InvalidScope verifies scope validation
func (s *OAuthFlowSuite) TestClientCredentialsGrant_InvalidScope() {
	// Create a confidential client with limited scopes
	clientSecret := s.mustGenerateRandomString(32)
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: clientSecret, Valid: true},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"admin:users:read"}, // Only read, not write
		IsConfidential: true,
		Audience:       "http://localhost:8080",
	})

	// Request scope that client is not allowed
	tokenValues := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {client.ClientID},
		"client_secret": {clientSecret},
		"scope":         {"admin:users:write"}, // Not allowed
	}
	resp, err := s.httpClient.PostForm("http://localhost:8080/oauth/token", tokenValues)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusBadRequest, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	var errorResponse map[string]string
	err = json.Unmarshal(body, &errorResponse)
	s.Require().NoError(err)
	s.Equal("invalid_scope", errorResponse["error"])
}

// TestClientCredentialsGrant_DefaultScopes verifies default scope behavior when none specified
func (s *OAuthFlowSuite) TestClientCredentialsGrant_DefaultScopes() {
	// Create a confidential client with multiple scopes
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

	// Request without specifying scope - should get all allowed scopes
	tokenValues := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {client.ClientID},
		"client_secret": {clientSecret},
		// No scope specified
	}
	resp, err := s.httpClient.PostForm("http://localhost:8080/oauth/token", tokenValues)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	var tokenResponse TokenResponse
	err = json.Unmarshal(body, &tokenResponse)
	s.Require().NoError(err)

	// Parse JWT and check scope
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(tokenResponse.AccessToken, jwt.MapClaims{})
	s.Require().NoError(err)

	claims := token.Claims.(jwt.MapClaims)
	scope := claims["scope"].(string)
	s.Contains(scope, "admin:users:read")
	s.Contains(scope, "admin:users:write")
}
