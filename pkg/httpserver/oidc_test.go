//go:build integration

package httpserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/eswan18/identity/pkg/db"
	"github.com/golang-jwt/jwt/v5"
)

// TestTokenResponseIncludesIDToken verifies that the token response includes an id_token
// when the openid scope is requested, per OIDC Core Section 3.1.3.3.
func (s *OAuthFlowSuite) TestTokenResponseIncludesIDToken() {
	result := s.mustCompleteOAuthFlow(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: "", Valid: false},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid", "profile", "email"},
		IsConfidential: false,
		Audience:       "http://localhost:8080",
	})

	// ID token should be present
	s.NotEmpty(result.TokenResponse.IDToken, "id_token should be present when openid scope is requested")

	// Parse the ID token to verify claims
	parts := strings.Split(result.TokenResponse.IDToken, ".")
	s.Require().Len(parts, 3, "id_token should be a valid JWT")

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	s.Require().NoError(err)

	var claims map[string]interface{}
	err = json.Unmarshal(payload, &claims)
	s.Require().NoError(err)

	// Required OIDC claims
	s.Equal(result.User.ID.String(), claims["sub"], "sub should be user ID")
	s.Equal("http://localhost:8080", claims["iss"], "issuer should match")
	s.NotNil(claims["exp"], "exp should be present")
	s.NotNil(claims["iat"], "iat should be present")
	s.NotNil(claims["at_hash"], "at_hash should be present")

	// Audience should be the client_id (not the resource server audience)
	// JWT aud claim is serialized as an array
	aud, ok := claims["aud"].([]interface{})
	s.Require().True(ok, "aud should be an array")
	s.Require().Len(aud, 1)
	s.Equal(result.Client.ClientID, aud[0], "audience should be client_id")

	// email scope claims
	s.Equal(result.User.Email, claims["email"], "email should match")
	s.Equal(false, claims["email_verified"], "new user should not be verified")

	// profile scope claims
	s.Equal(result.User.Username, claims["preferred_username"], "preferred_username should match")
}

// TestIDTokenIncludesNonce verifies that when a nonce is sent in the authorize request,
// it appears in the ID token per OIDC Core Section 3.1.2.1.
func (s *OAuthFlowSuite) TestIDTokenIncludesNonce() {
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: "", Valid: false},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid", "profile", "email"},
		IsConfidential: false,
		Audience:       "http://localhost:8080",
	})
	username := s.mustGenerateRandomString(8)
	password := s.mustGenerateRandomString(16)
	s.mustRegisterUser(username, password, fmt.Sprintf("%s@example.com", username))
	scv := s.mustCreateStateAndCodeVerifier()
	nonce := s.mustGenerateRandomString(32)

	// Create a client with cookie jar to maintain session
	jar, err := cookiejar.New(nil)
	s.Require().NoError(err)
	httpClient := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Login (with nonce) → authorize → consent → approve → callback with code
	resp, err := csrfPostFormLogin(s.T(), httpClient, "http://localhost:8080/oauth/login", url.Values{
		"username":              {username},
		"password":              {password},
		"client_id":             {client.ClientID},
		"redirect_uri":          {"http://localhost:8080/callback"},
		"state":                 {scv.State},
		"scope":                 {"openid profile email"},
		"code_challenge":        {scv.CodeChallenge},
		"code_challenge_method": {scv.CodeChallengeMethod},
		"nonce":                 {nonce},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)

	// Follow redirect to /oauth/authorize → /oauth/consent
	authorizeURL := resp.Header.Get("Location")
	if !strings.HasPrefix(authorizeURL, "http") {
		authorizeURL = "http://localhost:8080" + authorizeURL
	}
	resp, err = httpClient.Get(authorizeURL)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)

	// Approve consent
	consentLocation := resp.Header.Get("Location")
	consentURL, err := url.Parse(consentLocation)
	s.Require().NoError(err)
	resp, err = csrfPostFormLogin(s.T(), httpClient, "http://localhost:8080/oauth/consent", url.Values{
		"decision":              {"allow"},
		"client_id":             {consentURL.Query().Get("client_id")},
		"redirect_uri":          {consentURL.Query().Get("redirect_uri")},
		"response_type":         {consentURL.Query().Get("response_type")},
		"scope":                 {consentURL.Query().Get("scope")},
		"state":                 {consentURL.Query().Get("state")},
		"code_challenge":        {consentURL.Query().Get("code_challenge")},
		"code_challenge_method": {consentURL.Query().Get("code_challenge_method")},
		"nonce":                 {consentURL.Query().Get("nonce")},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)

	// Extract the authorization code from the redirect
	location := resp.Header.Get("Location")
	redirectURL, err := url.Parse(location)
	s.Require().NoError(err)
	authorizationCode := redirectURL.Query().Get("code")
	s.Require().NotEmpty(authorizationCode, "authorization code should be present")

	// Exchange the code for tokens
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authorizationCode},
		"redirect_uri":  {"http://localhost:8080/callback"},
		"client_id":     {client.ClientID},
		"code_verifier": {scv.CodeVerifier},
	}
	resp, err = httpClient.PostForm("http://localhost:8080/oauth/token", tokenForm)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)

	var tokenResponse TokenResponse
	err = json.Unmarshal(body, &tokenResponse)
	s.Require().NoError(err)
	s.Require().NotEmpty(tokenResponse.IDToken, "id_token should be present")

	// Parse the ID token and verify the nonce claim
	parts := strings.Split(tokenResponse.IDToken, ".")
	s.Require().Len(parts, 3, "id_token should be a valid JWT")

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	s.Require().NoError(err)

	var claims map[string]interface{}
	err = json.Unmarshal(payload, &claims)
	s.Require().NoError(err)

	s.Equal(nonce, claims["nonce"], "nonce in ID token should match the nonce sent in authorize request")
}

// TestIDTokenOmitsNonceWhenNotProvided verifies that when no nonce is sent,
// the ID token does not include a nonce claim.
func (s *OAuthFlowSuite) TestIDTokenOmitsNonceWhenNotProvided() {
	result := s.mustCompleteOAuthFlow(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: "", Valid: false},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid", "profile", "email"},
		IsConfidential: false,
		Audience:       "http://localhost:8080",
	})

	s.Require().NotEmpty(result.TokenResponse.IDToken)

	parts := strings.Split(result.TokenResponse.IDToken, ".")
	s.Require().Len(parts, 3)

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	s.Require().NoError(err)

	var claims map[string]interface{}
	err = json.Unmarshal(payload, &claims)
	s.Require().NoError(err)

	_, hasNonce := claims["nonce"]
	s.False(hasNonce, "nonce should not be present when not sent in authorize request")
}

// TestLoginGetPreservesNonce verifies that the login page renders the nonce from
// the query string into the hidden form field. Without this, a fresh login through
// the browser flow (authorize → login GET → login POST) strips the nonce, and the
// resulting ID token is missing the nonce claim — breaking clients like authlib
// that validate the nonce.
func (s *OAuthFlowSuite) TestLoginGetPreservesNonce() {
	nonce := s.mustGenerateRandomString(32)
	loginURL := "http://localhost:8080/oauth/login?" + url.Values{
		"client_id":             {"any"},
		"redirect_uri":          {"http://localhost:8080/callback"},
		"state":                 {"state"},
		"scope":                 {"openid"},
		"code_challenge":        {"challenge"},
		"code_challenge_method": {"S256"},
		"nonce":                 {nonce},
	}.Encode()

	resp, err := s.httpClient.Get(loginURL)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	s.Contains(string(body), fmt.Sprintf(`name="nonce" value="%s"`, nonce),
		"login page should render nonce from query string into hidden form field")
}

// TestIDTokenIncludesNonceThroughBrowserFlow verifies end-to-end that a nonce sent to
// /oauth/authorize survives the full browser flow (authorize → login GET → login POST →
// authorize → consent → token) and appears in the ID token. This guards against the
// earlier regression where HandleLoginGet silently dropped the nonce.
func (s *OAuthFlowSuite) TestIDTokenIncludesNonceThroughBrowserFlow() {
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: "", Valid: false},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid", "profile", "email"},
		IsConfidential: false,
		Audience:       "http://localhost:8080",
	})
	username := s.mustGenerateAlphanumericString(12)
	password := s.mustGenerateRandomString(16)
	s.mustRegisterUser(username, password, fmt.Sprintf("%s@example.com", username))
	scv := s.mustCreateStateAndCodeVerifier()
	nonce := s.mustGenerateRandomString(32)

	jar, err := cookiejar.New(nil)
	s.Require().NoError(err)
	httpClient := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Step 1: GET /oauth/authorize — user is unauthenticated, gets redirected to /oauth/login.
	authorizeQuery := url.Values{
		"response_type":         {"code"},
		"client_id":             {client.ClientID},
		"redirect_uri":          {"http://localhost:8080/callback"},
		"scope":                 {"openid profile email"},
		"state":                 {scv.State},
		"code_challenge":        {scv.CodeChallenge},
		"code_challenge_method": {scv.CodeChallengeMethod},
		"nonce":                 {nonce},
	}
	resp, err := httpClient.Get("http://localhost:8080/oauth/authorize?" + authorizeQuery.Encode())
	s.Require().NoError(err)
	s.Require().NoError(resp.Body.Close())
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	loginLocation := resp.Header.Get("Location")
	if !strings.HasPrefix(loginLocation, "http") {
		loginLocation = "http://localhost:8080" + loginLocation
	}

	// Step 2: GET the login page to retrieve the rendered form (the browser step).
	resp, err = httpClient.Get(loginLocation)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, resp.StatusCode)
	loginBody, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	s.Require().NoError(resp.Body.Close())
	s.Require().Contains(string(loginBody), fmt.Sprintf(`name="nonce" value="%s"`, nonce),
		"login form must include the nonce so the browser submits it back")

	// Step 3: POST login credentials — simulate the form submit. Mirror what the
	// rendered form would send, sourcing values from the login URL query string.
	loginURL, err := url.Parse(loginLocation)
	s.Require().NoError(err)
	loginForm := url.Values{
		"username":              {username},
		"password":              {password},
		"client_id":             {loginURL.Query().Get("client_id")},
		"redirect_uri":          {loginURL.Query().Get("redirect_uri")},
		"state":                 {loginURL.Query().Get("state")},
		"scope":                 {loginURL.Query().Get("scope")},
		"code_challenge":        {loginURL.Query().Get("code_challenge")},
		"code_challenge_method": {loginURL.Query().Get("code_challenge_method")},
		"nonce":                 {loginURL.Query().Get("nonce")},
	}
	resp, err = csrfPostFormLogin(s.T(), httpClient, "http://localhost:8080/oauth/login", loginForm)
	s.Require().NoError(err)
	s.Require().NoError(resp.Body.Close())
	s.Require().Equal(http.StatusFound, resp.StatusCode)

	// Step 4: Follow redirect to /oauth/authorize, which now sees session and redirects to consent.
	authorizeLocation := resp.Header.Get("Location")
	if !strings.HasPrefix(authorizeLocation, "http") {
		authorizeLocation = "http://localhost:8080" + authorizeLocation
	}
	resp, err = httpClient.Get(authorizeLocation)
	s.Require().NoError(err)
	s.Require().NoError(resp.Body.Close())
	s.Require().Equal(http.StatusFound, resp.StatusCode)

	// Step 5: Approve consent.
	consentLocation := resp.Header.Get("Location")
	consentURL, err := url.Parse(consentLocation)
	s.Require().NoError(err)
	consentForm := url.Values{
		"decision":              {"allow"},
		"client_id":             {consentURL.Query().Get("client_id")},
		"redirect_uri":          {consentURL.Query().Get("redirect_uri")},
		"response_type":         {consentURL.Query().Get("response_type")},
		"scope":                 {consentURL.Query().Get("scope")},
		"state":                 {consentURL.Query().Get("state")},
		"code_challenge":        {consentURL.Query().Get("code_challenge")},
		"code_challenge_method": {consentURL.Query().Get("code_challenge_method")},
		"nonce":                 {consentURL.Query().Get("nonce")},
	}
	resp, err = csrfPostFormLogin(s.T(), httpClient, "http://localhost:8080/oauth/consent", consentForm)
	s.Require().NoError(err)
	s.Require().NoError(resp.Body.Close())
	s.Require().Equal(http.StatusFound, resp.StatusCode)

	// Step 6: Extract the authorization code and exchange for tokens.
	callbackLocation := resp.Header.Get("Location")
	callbackURL, err := url.Parse(callbackLocation)
	s.Require().NoError(err)
	authorizationCode := callbackURL.Query().Get("code")
	s.Require().NotEmpty(authorizationCode)

	resp, err = httpClient.PostForm("http://localhost:8080/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authorizationCode},
		"redirect_uri":  {"http://localhost:8080/callback"},
		"client_id":     {client.ClientID},
		"code_verifier": {scv.CodeVerifier},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	var tokenResponse TokenResponse
	s.Require().NoError(json.Unmarshal(body, &tokenResponse))
	s.Require().NotEmpty(tokenResponse.IDToken)

	parts := strings.Split(tokenResponse.IDToken, ".")
	s.Require().Len(parts, 3)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	s.Require().NoError(err)
	var claims map[string]interface{}
	s.Require().NoError(json.Unmarshal(payload, &claims))
	s.Equal(nonce, claims["nonce"], "nonce must survive the full browser login flow")
}

// TestTokenResponseIDTokenAbsentWithoutOpenID verifies that no id_token is returned
// when the openid scope is not requested.
func (s *OAuthFlowSuite) TestTokenResponseIDTokenAbsentWithoutOpenID() {
	// Create a client that only has admin scopes (no openid)
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

	// Use client credentials (no openid scope)
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {client.ClientID},
		"client_secret": {clientSecret},
		"scope":         {"admin:users:read"},
	}
	resp, err := s.httpClient.PostForm("http://localhost:8080/oauth/token", form)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)

	// Verify no id_token field in response
	var rawResponse map[string]interface{}
	err = json.Unmarshal(body, &rawResponse)
	s.Require().NoError(err)
	s.NotContains(rawResponse, "id_token", "id_token should not be present without openid scope")
}

// TestJWKSEndpoint verifies that clients can fetch and parse the public key.
func (s *OAuthFlowSuite) TestJWKSEndpoint() {
	resp, err := s.httpClient.Get("http://localhost:8080/.well-known/jwks.json")
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)

	// Verify content type
	s.Contains(resp.Header.Get("Content-Type"), "application/json")

	// Parse response
	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)

	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	err = json.Unmarshal(body, &jwks)
	s.Require().NoError(err)

	// Verify at least one key exists
	s.Require().NotEmpty(jwks.Keys, "JWKS should contain at least one key")

	// Verify key structure
	key := jwks.Keys[0]
	s.Equal("EC", key["kty"], "key type should be EC")
	s.Equal("P-256", key["crv"], "curve should be P-256")
	s.Equal("ES256", key["alg"], "algorithm should be ES256")
	s.Equal("sig", key["use"], "use should be sig")
	s.NotEmpty(key["kid"], "kid should be present")
	s.NotEmpty(key["x"], "x coordinate should be present")
	s.NotEmpty(key["y"], "y coordinate should be present")
}

// TestClientCanValidateAccessToken simulates what a real OAuth client does:
// fetch the JWKS, parse the JWT, verify the signature, and validate claims.
func (s *OAuthFlowSuite) TestClientCanValidateAccessToken() {
	// Complete OAuth flow to get an access token
	result := s.mustCompleteOAuthFlow(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: "", Valid: false},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid", "profile", "email"},
		IsConfidential: false,
		Audience:       "http://localhost:8000",
	})

	accessToken := result.TokenResponse.AccessToken
	s.Require().NotEmpty(accessToken)

	// Step 1: Fetch JWKS
	resp, err := s.httpClient.Get("http://localhost:8080/.well-known/jwks.json")
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)

	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
			Kid string `json:"kid"`
			Alg string `json:"alg"`
		} `json:"keys"`
	}
	err = json.Unmarshal(body, &jwks)
	s.Require().NoError(err)
	s.Require().NotEmpty(jwks.Keys)

	// Step 2: Parse JWT header to get kid
	parts := strings.Split(accessToken, ".")
	s.Require().Len(parts, 3, "JWT should have 3 parts")

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	s.Require().NoError(err)

	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	err = json.Unmarshal(headerBytes, &header)
	s.Require().NoError(err)
	s.Equal("ES256", header.Alg)
	s.Equal("JWT", header.Typ)

	// Step 3: Find matching key in JWKS
	var matchingKey *struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
		Kid string `json:"kid"`
		Alg string `json:"alg"`
	}
	for i := range jwks.Keys {
		if jwks.Keys[i].Kid == header.Kid {
			matchingKey = &jwks.Keys[i]
			break
		}
	}
	s.Require().NotNil(matchingKey, "should find matching key in JWKS")

	// Step 4: Construct ECDSA public key from JWKS
	xBytes, err := base64.RawURLEncoding.DecodeString(matchingKey.X)
	s.Require().NoError(err)
	yBytes, err := base64.RawURLEncoding.DecodeString(matchingKey.Y)
	s.Require().NoError(err)

	publicKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}

	// Step 5: Parse and validate the JWT
	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (any, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})
	s.Require().NoError(err)
	s.True(token.Valid, "token should be valid")

	// Step 6: Validate claims
	claims, ok := token.Claims.(jwt.MapClaims)
	s.Require().True(ok, "claims should be MapClaims")

	// Verify standard claims
	s.Equal("http://localhost:8080", claims["iss"], "issuer should match")
	// Audience can be a string or array depending on JWT library behavior
	switch aud := claims["aud"].(type) {
	case string:
		s.Equal(result.Client.Audience, aud, "audience should match client's audience")
	case []any:
		s.Require().NotEmpty(aud, "audience array should not be empty")
		s.Equal(result.Client.Audience, aud[0], "audience should match client's audience")
	default:
		s.Fail("unexpected audience type")
	}
	s.Equal(result.User.ID.String(), claims["sub"], "subject should be user ID")

	// Verify expiration is in the future
	exp, ok := claims["exp"].(float64)
	s.Require().True(ok, "exp should be a number")
	s.Greater(int64(exp), time.Now().Unix(), "token should not be expired")

	// Verify custom claims
	s.Equal(result.User.Username, claims["username"], "username should match")
	s.Equal(result.User.Email, claims["email"], "email should match")
	s.Equal("openid profile email", claims["scope"], "scope should match")
}

// TestUserInfoEndpoint verifies that clients can get user profile data with an access token.
func (s *OAuthFlowSuite) TestUserInfoEndpoint() {
	// Complete OAuth flow to get an access token
	result := s.mustCompleteOAuthFlow(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: "", Valid: false},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid", "profile", "email"},
		IsConfidential: false,
		Audience:       "http://localhost:8000",
	})

	accessToken := result.TokenResponse.AccessToken
	s.Require().NotEmpty(accessToken)

	// Call userinfo endpoint with Bearer token
	req, err := http.NewRequest("GET", "http://localhost:8080/oauth/userinfo", nil)
	s.Require().NoError(err)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := s.httpClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)

	// Parse response
	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)

	var userInfo struct {
		Sub           string `json:"sub"`
		Username      string `json:"username"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	err = json.Unmarshal(body, &userInfo)
	s.Require().NoError(err)

	// Verify claims match the test user
	s.Equal(result.User.ID.String(), userInfo.Sub, "sub should be user ID")
	s.Equal(result.User.Username, userInfo.Username, "username should match")
	s.Equal(result.User.Email, userInfo.Email, "email should match")
	s.False(userInfo.EmailVerified, "email_verified should be false for new unverified user")
}

// TestUserInfoScopeGating verifies that UserInfo only returns claims for requested scopes.
// Per OIDC Core Section 5.4, email/email_verified require "email" scope, and
// username/given_name/family_name/picture require "profile" scope.
func (s *OAuthFlowSuite) TestUserInfoScopeGating() {
	// Complete OAuth flow with only "openid" scope (no email or profile)
	result := s.mustCompleteOAuthFlow(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: "", Valid: false},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid", "profile", "email"},
		IsConfidential: false,
		Audience:       "http://localhost:8000",
	}, "openid") // only request openid scope

	accessToken := result.TokenResponse.AccessToken
	s.Require().NotEmpty(accessToken)

	// Call userinfo endpoint
	req, err := http.NewRequest("GET", "http://localhost:8080/oauth/userinfo", nil)
	s.Require().NoError(err)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := s.httpClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)

	var userInfo map[string]interface{}
	err = json.Unmarshal(body, &userInfo)
	s.Require().NoError(err)

	// "sub" should always be present
	s.Contains(userInfo, "sub", "sub should always be present")
	s.Equal(result.User.ID.String(), userInfo["sub"], "sub should be user ID")

	// Claims gated by "email" scope should be absent
	s.NotContains(userInfo, "email", "email should not be present without email scope")
	s.NotContains(userInfo, "email_verified", "email_verified should not be present without email scope")

	// Claims gated by "profile" scope should be absent
	s.NotContains(userInfo, "username", "username should not be present without profile scope")
	s.NotContains(userInfo, "given_name", "given_name should not be present without profile scope")
	s.NotContains(userInfo, "family_name", "family_name should not be present without profile scope")
	s.NotContains(userInfo, "picture", "picture should not be present without profile scope")
}

// TestUserInfoRejectsRevokedToken verifies that a revoked access token is
// rejected at the UserInfo endpoint with 401 invalid_token, consistent with
// the introspection endpoint's handling of revoked tokens. This guards
// against a regression of the vulnerability where UserInfo treated a
// missing/revoked JTI row as "revocation tracking not enabled" and let the
// request through.
func (s *OAuthFlowSuite) TestUserInfoRejectsRevokedToken() {
	// Revocation requires confidential-client authentication (RFC 7009 §2.1), and the server
	// enforces that a client can only revoke tokens issued to itself (RFC 7009 §2.1
	// ownership check). So the same confidential client must both obtain and revoke the
	// token here.
	clientSecret := s.mustGenerateRandomString(32)
	result := s.mustCompleteOAuthFlow(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: clientSecret, Valid: true},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid", "profile", "email"},
		IsConfidential: true,
		Audience:       "http://localhost:8000",
	})
	accessToken := result.TokenResponse.AccessToken
	s.Require().NotEmpty(accessToken)

	// Sanity check: userinfo works before revocation.
	req, err := http.NewRequest("GET", "http://localhost:8080/oauth/userinfo", nil)
	s.Require().NoError(err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := s.httpClient.Do(req)
	s.Require().NoError(err)
	resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode, "userinfo should succeed before revocation")

	// Revoke the access token, using the same client it was issued to.
	revokeValues := url.Values{
		"token":           {accessToken},
		"token_type_hint": {"access_token"},
		"client_id":       {result.Client.ClientID},
		"client_secret":   {clientSecret},
	}
	resp, err = s.httpClient.PostForm("http://localhost:8080/oauth/revoke", revokeValues)
	s.Require().NoError(err)
	resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)

	// UserInfo must now reject the revoked token.
	req, err = http.NewRequest("GET", "http://localhost:8080/oauth/userinfo", nil)
	s.Require().NoError(err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err = s.httpClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusUnauthorized, resp.StatusCode, "userinfo should reject a revoked access token")

	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	var errResponse map[string]string
	err = json.Unmarshal(body, &errResponse)
	s.Require().NoError(err)
	s.Equal("invalid_token", errResponse["error"])
}

// TestUserInfoEmailScopeOnly verifies that requesting "openid email" returns
// email claims but not profile claims.
func (s *OAuthFlowSuite) TestUserInfoEmailScopeOnly() {
	result := s.mustCompleteOAuthFlow(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: "", Valid: false},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid", "profile", "email"},
		IsConfidential: false,
		Audience:       "http://localhost:8000",
	}, "openid email")

	req, err := http.NewRequest("GET", "http://localhost:8080/oauth/userinfo", nil)
	s.Require().NoError(err)
	req.Header.Set("Authorization", "Bearer "+result.TokenResponse.AccessToken)

	resp, err := s.httpClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)

	var userInfo map[string]interface{}
	err = json.Unmarshal(body, &userInfo)
	s.Require().NoError(err)

	// "sub" always present
	s.Contains(userInfo, "sub")

	// "email" scope claims should be present
	s.Contains(userInfo, "email", "email should be present with email scope")
	s.Contains(userInfo, "email_verified", "email_verified should be present with email scope")
	s.Equal(result.User.Email, userInfo["email"])
	s.Equal(false, userInfo["email_verified"], "new user should not be verified")

	// "profile" scope claims should be absent
	s.NotContains(userInfo, "username", "username should not be present without profile scope")
	s.NotContains(userInfo, "given_name", "given_name should not be present without profile scope")
	s.NotContains(userInfo, "family_name", "family_name should not be present without profile scope")
	s.NotContains(userInfo, "picture", "picture should not be present without profile scope")
}

func (s *OAuthFlowSuite) TestOIDCDiscoveryEndpoint() {
	resp, err := s.httpClient.Get("http://localhost:8080/.well-known/openid-configuration")
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)

	// Verify content type
	s.Contains(resp.Header.Get("Content-Type"), "application/json")

	// Parse response
	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)

	var discovery map[string]interface{}
	err = json.Unmarshal(body, &discovery)
	s.Require().NoError(err)

	// Verify required fields per OpenID Connect Discovery 1.0
	s.Equal("http://localhost:8080", discovery["issuer"])
	s.Equal("http://localhost:8080/oauth/authorize", discovery["authorization_endpoint"])
	s.Equal("http://localhost:8080/oauth/token", discovery["token_endpoint"])
	s.Equal("http://localhost:8080/.well-known/jwks.json", discovery["jwks_uri"])

	// Verify recommended fields
	s.Equal("http://localhost:8080/oauth/userinfo", discovery["userinfo_endpoint"])
	s.Contains(discovery["scopes_supported"], "openid")
	s.Contains(discovery["response_types_supported"], "code")
	s.Contains(discovery["grant_types_supported"], "authorization_code")
	s.Contains(discovery["grant_types_supported"], "refresh_token")
	s.Contains(discovery["subject_types_supported"], "public")
	s.Contains(discovery["id_token_signing_alg_values_supported"], "ES256")
	s.Contains(discovery["code_challenge_methods_supported"], "S256")

	// Verify additional endpoints
	s.Equal("http://localhost:8080/oauth/introspect", discovery["introspection_endpoint"])
	s.Equal("http://localhost:8080/oauth/revoke", discovery["revocation_endpoint"])
	s.Equal("http://localhost:8080/oauth/logout", discovery["end_session_endpoint"])

	// claims_supported should list actually-returned claims, not "name"
	claimsSupported := discovery["claims_supported"].([]interface{})
	s.NotContains(claimsSupported, "name", "claims_supported should not list 'name' (never returned)")
	s.Contains(claimsSupported, "preferred_username")
	s.Contains(claimsSupported, "given_name")
	s.Contains(claimsSupported, "family_name")
	s.Contains(claimsSupported, "picture")
	s.Contains(claimsSupported, "at_hash")

	// registration_endpoint should not be present (not RFC 7591 dynamic registration)
	s.Nil(discovery["registration_endpoint"], "registration_endpoint should not be present (not RFC 7591 dynamic registration)")
}

func (s *OAuthFlowSuite) TestOIDCDiscoveryCORSHeaders() {
	// Test that CORS headers are set on GET requests
	req, err := http.NewRequest("GET", "http://localhost:8080/.well-known/openid-configuration", nil)
	s.Require().NoError(err)
	req.Header.Set("Origin", "https://example.com")

	resp, err := s.httpClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()

	// Should return 200 OK with CORS headers
	s.Equal(http.StatusOK, resp.StatusCode)
	s.Equal("*", resp.Header.Get("Access-Control-Allow-Origin"))
}
