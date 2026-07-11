//go:build integration

package httpserver

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/eswan18/identity/pkg/db"
)

func (s *OAuthFlowSuite) TestTokenIntrospectionAccessToken() {
	// Create a confidential client for introspection (needs client_secret)
	clientSecret := s.mustGenerateRandomString(32)
	introspectClient := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: clientSecret, Valid: true},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid", "profile", "email"},
		IsConfidential: true,
		Audience:       "http://localhost:8000",
	})

	// Create a public client to obtain tokens (easier flow)
	tokenClient := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: "", Valid: false},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid", "profile", "email"},
		IsConfidential: false,
		Audience:       "http://localhost:8000",
	})

	// Complete OAuth flow to get an access token using public client
	user := s.mustRegisterUser(
		s.mustGenerateRandomString(8),
		s.mustGenerateRandomString(8),
		fmt.Sprintf("%s@example.com", s.mustGenerateRandomString(8)),
	)
	scv := s.mustCreateStateAndCodeVerifier()
	authCode := s.mustLoginAndConsent(user, tokenClient.ClientID, tokenClient.RedirectUris[0], "openid profile email", scv)

	// Exchange code for tokens
	tokenValues := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {tokenClient.RedirectUris[0]},
		"client_id":     {tokenClient.ClientID},
		"code_verifier": {scv.CodeVerifier},
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

	// Now introspect the access token using the confidential client
	introspectValues := url.Values{
		"token":           {tokenResponse.AccessToken},
		"token_type_hint": {"access_token"},
		"client_id":       {introspectClient.ClientID},
		"client_secret":   {clientSecret},
	}
	resp, err = s.httpClient.PostForm("http://localhost:8080/oauth/introspect", introspectValues)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)

	body, err = io.ReadAll(resp.Body)
	s.Require().NoError(err)

	var introspectResponse map[string]interface{}
	err = json.Unmarshal(body, &introspectResponse)
	s.Require().NoError(err)

	// Verify the token is active
	s.True(introspectResponse["active"].(bool), "token should be active")
	s.Equal(user.Username, introspectResponse["username"])
	s.Equal(user.ID.String(), introspectResponse["sub"])
	s.Equal("openid profile email", introspectResponse["scope"])
	s.Equal("http://localhost:8080", introspectResponse["iss"])
	s.NotNil(introspectResponse["exp"])
	s.NotNil(introspectResponse["iat"])
}

func (s *OAuthFlowSuite) TestTokenIntrospectionRefreshToken() {
	// Create a confidential client for introspection (needs client_secret)
	clientSecret := s.mustGenerateRandomString(32)
	introspectClient := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: clientSecret, Valid: true},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid", "profile", "email"},
		IsConfidential: true,
		Audience:       "http://localhost:8000",
	})

	// Create a public client to obtain tokens (easier flow)
	tokenClient := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: "", Valid: false},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid", "profile", "email"},
		IsConfidential: false,
		Audience:       "http://localhost:8000",
	})

	// Complete OAuth flow to get tokens using public client
	user := s.mustRegisterUser(
		s.mustGenerateRandomString(8),
		s.mustGenerateRandomString(8),
		fmt.Sprintf("%s@example.com", s.mustGenerateRandomString(8)),
	)
	scv := s.mustCreateStateAndCodeVerifier()

	authCode := s.mustLoginAndConsent(user, tokenClient.ClientID, tokenClient.RedirectUris[0], "openid profile email", scv)

	tokenValues := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {tokenClient.RedirectUris[0]},
		"client_id":     {tokenClient.ClientID},
		"code_verifier": {scv.CodeVerifier},
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

	// Now introspect the refresh token using the confidential client
	introspectValues := url.Values{
		"token":           {tokenResponse.RefreshToken},
		"token_type_hint": {"refresh_token"},
		"client_id":       {introspectClient.ClientID},
		"client_secret":   {clientSecret},
	}
	resp, err = s.httpClient.PostForm("http://localhost:8080/oauth/introspect", introspectValues)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)

	body, err = io.ReadAll(resp.Body)
	s.Require().NoError(err)

	var introspectResponse map[string]interface{}
	err = json.Unmarshal(body, &introspectResponse)
	s.Require().NoError(err)

	// Verify the refresh token is active
	s.True(introspectResponse["active"].(bool), "refresh token should be active")
	s.Equal(user.Username, introspectResponse["username"])
	s.Equal(user.ID.String(), introspectResponse["sub"])
	s.Equal("openid profile email", introspectResponse["scope"])
	s.Equal("refresh_token", introspectResponse["token_type"])
}

func (s *OAuthFlowSuite) TestTokenIntrospectionInvalidToken() {
	// Create a confidential client
	clientSecret := s.mustGenerateRandomString(32)
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: clientSecret, Valid: true},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid"},
		IsConfidential: true,
		Audience:       "http://localhost:8000",
	})

	// Introspect an invalid token
	introspectValues := url.Values{
		"token":         {"invalid-token-12345"},
		"client_id":     {client.ClientID},
		"client_secret": {clientSecret},
	}
	resp, err := s.httpClient.PostForm("http://localhost:8080/oauth/introspect", introspectValues)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)

	var introspectResponse map[string]interface{}
	err = json.Unmarshal(body, &introspectResponse)
	s.Require().NoError(err)

	// Per RFC 7662, invalid tokens return active: false
	s.False(introspectResponse["active"].(bool), "invalid token should not be active")
}

func (s *OAuthFlowSuite) TestTokenIntrospectionInvalidClientCredentials() {
	// Create a confidential client
	clientSecret := s.mustGenerateRandomString(32)
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: clientSecret, Valid: true},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid"},
		IsConfidential: true,
		Audience:       "http://localhost:8000",
	})

	// Try to introspect with wrong client secret
	introspectValues := url.Values{
		"token":         {"some-token"},
		"client_id":     {client.ClientID},
		"client_secret": {"wrong-secret"},
	}
	resp, err := s.httpClient.PostForm("http://localhost:8080/oauth/introspect", introspectValues)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusUnauthorized, resp.StatusCode)
}

func (s *OAuthFlowSuite) TestTokenIntrospectionMissingToken() {
	// Create a confidential client
	clientSecret := s.mustGenerateRandomString(32)
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: clientSecret, Valid: true},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid"},
		IsConfidential: true,
		Audience:       "http://localhost:8000",
	})

	// Try to introspect without a token
	introspectValues := url.Values{
		"client_id":     {client.ClientID},
		"client_secret": {clientSecret},
	}
	resp, err := s.httpClient.PostForm("http://localhost:8080/oauth/introspect", introspectValues)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusBadRequest, resp.StatusCode)
}

func (s *OAuthFlowSuite) TestTokenRevocationAccessToken() {
	// Revocation now requires confidential-client authentication (RFC 7009 §2.1), and the
	// server enforces that a client can only revoke tokens issued to itself. So the client
	// that obtains the tokens and the client that revokes them must be the same confidential
	// client (unlike introspection, which doesn't require token ownership).
	clientSecret := s.mustGenerateRandomString(32)
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: clientSecret, Valid: true},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid", "profile", "email"},
		IsConfidential: true,
		Audience:       "http://localhost:8000",
	})

	// Complete OAuth flow to get tokens
	user := s.mustRegisterUser(
		s.mustGenerateRandomString(8),
		s.mustGenerateRandomString(8),
		fmt.Sprintf("%s@example.com", s.mustGenerateRandomString(8)),
	)
	scv := s.mustCreateStateAndCodeVerifier()

	authCode := s.mustLoginAndConsent(user, client.ClientID, client.RedirectUris[0], "openid profile email", scv)

	tokenValues := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {client.RedirectUris[0]},
		"client_id":     {client.ClientID},
		"client_secret": {clientSecret},
		"code_verifier": {scv.CodeVerifier},
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

	// Verify token is active before revocation
	introspectValues := url.Values{
		"token":           {tokenResponse.AccessToken},
		"token_type_hint": {"access_token"},
		"client_id":       {client.ClientID},
		"client_secret":   {clientSecret},
	}
	resp, err = s.httpClient.PostForm("http://localhost:8080/oauth/introspect", introspectValues)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)

	body, err = io.ReadAll(resp.Body)
	s.Require().NoError(err)
	var introspectResponse map[string]interface{}
	err = json.Unmarshal(body, &introspectResponse)
	s.Require().NoError(err)
	s.True(introspectResponse["active"].(bool), "token should be active before revocation")

	// Revoke the access token, using the same client that the token was issued to
	revokeValues := url.Values{
		"token":           {tokenResponse.AccessToken},
		"token_type_hint": {"access_token"},
		"client_id":       {client.ClientID},
		"client_secret":   {clientSecret},
	}
	resp, err = s.httpClient.PostForm("http://localhost:8080/oauth/revoke", revokeValues)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)

	// Verify token is no longer active after revocation
	resp, err = s.httpClient.PostForm("http://localhost:8080/oauth/introspect", introspectValues)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)

	body, err = io.ReadAll(resp.Body)
	s.Require().NoError(err)
	err = json.Unmarshal(body, &introspectResponse)
	s.Require().NoError(err)
	s.False(introspectResponse["active"].(bool), "token should be inactive after revocation")
}

// TestTokenRevocationRejectsOtherClient verifies the RFC 7009 §2.1 ownership check: a
// confidential client cannot revoke a token that was issued to a *different* client, even
// though it authenticates successfully. The revoke call must still return 200 OK (per RFC
// 7009, to avoid leaking token validity), but the token must remain active afterward.
func (s *OAuthFlowSuite) TestTokenRevocationRejectsOtherClient() {
	// The client that will obtain (and own) the tokens.
	ownerSecret := s.mustGenerateRandomString(32)
	ownerClient := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: ownerSecret, Valid: true},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid", "profile", "email"},
		IsConfidential: true,
		Audience:       "http://localhost:8000",
	})

	// A different, unrelated confidential client that will attempt the revocation.
	attackerSecret := s.mustGenerateRandomString(32)
	attackerClient := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: attackerSecret, Valid: true},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid", "profile", "email"},
		IsConfidential: true,
		Audience:       "http://localhost:8000",
	})

	user := s.mustRegisterUser(
		s.mustGenerateRandomString(8),
		s.mustGenerateRandomString(8),
		fmt.Sprintf("%s@example.com", s.mustGenerateRandomString(8)),
	)
	scv := s.mustCreateStateAndCodeVerifier()

	authCode := s.mustLoginAndConsent(user, ownerClient.ClientID, ownerClient.RedirectUris[0], "openid profile email", scv)

	tokenValues := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {ownerClient.RedirectUris[0]},
		"client_id":     {ownerClient.ClientID},
		"client_secret": {ownerSecret},
		"code_verifier": {scv.CodeVerifier},
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

	// The attacker client attempts to revoke a token it does not own.
	revokeValues := url.Values{
		"token":           {tokenResponse.AccessToken},
		"token_type_hint": {"access_token"},
		"client_id":       {attackerClient.ClientID},
		"client_secret":   {attackerSecret},
	}
	resp, err = s.httpClient.PostForm("http://localhost:8080/oauth/revoke", revokeValues)
	s.Require().NoError(err)
	defer resp.Body.Close()
	// RFC 7009 says revocation always returns 200, even when nothing was actually revoked.
	s.Equal(http.StatusOK, resp.StatusCode)

	// The token must still be active — the attacker's client must not have been able to
	// revoke a token that belongs to a different client.
	introspectValues := url.Values{
		"token":           {tokenResponse.AccessToken},
		"token_type_hint": {"access_token"},
		"client_id":       {ownerClient.ClientID},
		"client_secret":   {ownerSecret},
	}
	resp, err = s.httpClient.PostForm("http://localhost:8080/oauth/introspect", introspectValues)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)

	body, err = io.ReadAll(resp.Body)
	s.Require().NoError(err)
	var introspectResponse map[string]interface{}
	err = json.Unmarshal(body, &introspectResponse)
	s.Require().NoError(err)
	s.True(introspectResponse["active"].(bool), "token must remain active after a non-owning client's revoke attempt")
}

func (s *OAuthFlowSuite) TestTokenRevocationRefreshToken() {
	// Revocation now requires confidential-client authentication (RFC 7009 §2.1), and the
	// server enforces that a client can only revoke tokens issued to itself. So the client
	// that obtains the tokens and the client that revokes them must be the same confidential
	// client (unlike introspection, which doesn't require token ownership).
	clientSecret := s.mustGenerateRandomString(32)
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: clientSecret, Valid: true},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid", "profile", "email"},
		IsConfidential: true,
		Audience:       "http://localhost:8000",
	})

	// Complete OAuth flow to get tokens
	user := s.mustRegisterUser(
		s.mustGenerateRandomString(8),
		s.mustGenerateRandomString(8),
		fmt.Sprintf("%s@example.com", s.mustGenerateRandomString(8)),
	)
	scv := s.mustCreateStateAndCodeVerifier()

	authCode := s.mustLoginAndConsent(user, client.ClientID, client.RedirectUris[0], "openid profile email", scv)

	tokenValues := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {client.RedirectUris[0]},
		"client_id":     {client.ClientID},
		"client_secret": {clientSecret},
		"code_verifier": {scv.CodeVerifier},
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

	// Verify refresh token is active before revocation
	introspectValues := url.Values{
		"token":           {tokenResponse.RefreshToken},
		"token_type_hint": {"refresh_token"},
		"client_id":       {client.ClientID},
		"client_secret":   {clientSecret},
	}
	resp, err = s.httpClient.PostForm("http://localhost:8080/oauth/introspect", introspectValues)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)

	body, err = io.ReadAll(resp.Body)
	s.Require().NoError(err)
	var introspectResponse map[string]interface{}
	err = json.Unmarshal(body, &introspectResponse)
	s.Require().NoError(err)
	s.True(introspectResponse["active"].(bool), "refresh token should be active before revocation")

	// Revoke the refresh token, using the same client that the token was issued to
	revokeValues := url.Values{
		"token":           {tokenResponse.RefreshToken},
		"token_type_hint": {"refresh_token"},
		"client_id":       {client.ClientID},
		"client_secret":   {clientSecret},
	}
	resp, err = s.httpClient.PostForm("http://localhost:8080/oauth/revoke", revokeValues)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)

	// Verify refresh token is no longer active after revocation
	resp, err = s.httpClient.PostForm("http://localhost:8080/oauth/introspect", introspectValues)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)

	body, err = io.ReadAll(resp.Body)
	s.Require().NoError(err)
	err = json.Unmarshal(body, &introspectResponse)
	s.Require().NoError(err)
	s.False(introspectResponse["active"].(bool), "refresh token should be inactive after revocation")
}

func (s *OAuthFlowSuite) TestTokenRevocationInvalidToken() {
	// Create a confidential client
	clientSecret := s.mustGenerateRandomString(32)
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: clientSecret, Valid: true},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid"},
		IsConfidential: true,
		Audience:       "http://localhost:8000",
	})

	// Revoke an invalid token - should still return 200 OK per RFC 7009
	revokeValues := url.Values{
		"token":         {"invalid-token-12345"},
		"client_id":     {client.ClientID},
		"client_secret": {clientSecret},
	}
	resp, err := s.httpClient.PostForm("http://localhost:8080/oauth/revoke", revokeValues)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)
}

func (s *OAuthFlowSuite) TestTokenRevocationInvalidClientCredentials() {
	// Create a confidential client
	clientSecret := s.mustGenerateRandomString(32)
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: clientSecret, Valid: true},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid"},
		IsConfidential: true,
		Audience:       "http://localhost:8000",
	})

	// Try to revoke with wrong client secret
	revokeValues := url.Values{
		"token":         {"some-token"},
		"client_id":     {client.ClientID},
		"client_secret": {"wrong-secret"},
	}
	resp, err := s.httpClient.PostForm("http://localhost:8080/oauth/revoke", revokeValues)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusUnauthorized, resp.StatusCode)
}

func (s *OAuthFlowSuite) TestTokenRevocationMissingToken() {
	// Create a confidential client
	clientSecret := s.mustGenerateRandomString(32)
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: clientSecret, Valid: true},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid"},
		IsConfidential: true,
		Audience:       "http://localhost:8000",
	})

	// Try to revoke without a token
	revokeValues := url.Values{
		"client_id":     {client.ClientID},
		"client_secret": {clientSecret},
	}
	resp, err := s.httpClient.PostForm("http://localhost:8080/oauth/revoke", revokeValues)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusBadRequest, resp.StatusCode)
}
