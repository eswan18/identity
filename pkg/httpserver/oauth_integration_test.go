// /* //go:build integration */

package httpserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eswan18/identity/pkg/auth"
	"github.com/eswan18/identity/pkg/config"
	"github.com/eswan18/identity/pkg/db"
	"github.com/eswan18/identity/pkg/email"
	"github.com/eswan18/identity/pkg/mfa"
	"github.com/eswan18/identity/pkg/store"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

const (
	testPgVersion  = "17"
	testPgUser     = "postgres"
	testPgPassword = "postgres"
	testPgDatabase = "identity"
)

const testJWTPrivateKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEICQMNHONu2Sud2tu6jgOZs3LIj5yOZr89NBMLYiyqBK/oAoGCCqGSM49
AwEHoUQDQgAERCHWHrX20emk31HypGNgptwBjdZOyBybV/9BLTbJPj8UsZ/46ri5
/eFKkRfNApxFU/5lk1RGQJqt8t0GvkkJdw==
-----END EC PRIVATE KEY-----`

type UserWithPassword struct {
	db.AuthUser
	Password string
}

type StateAndCodeVerifier struct {
	State               string
	CodeVerifier        string
	CodeChallenge       string
	CodeChallengeMethod string
}

// OAuthFlowResult holds the result of completing an OAuth flow.
type OAuthFlowResult struct {
	Client        db.OauthClient
	User          UserWithPassword
	TokenResponse TokenResponse
}

type OAuthFlowSuite struct {
	suite.Suite
	httpClient  *http.Client
	pgContainer *postgres.PostgresContainer
	datastore   *store.Store
	server      *Server
}

func (s *OAuthFlowSuite) SetupSuite() {
	var err error
	s.httpClient = &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	s.pgContainer = prepareDatabase(s.T())
	dbURL, err := s.pgContainer.ConnectionString(s.T().Context(), "sslmode=disable")
	s.NoError(err)
	s.datastore, err = store.New(dbURL)
	s.NoError(err)

	config := &config.Config{
		HTTPAddress:   ":8080",
		TemplatesDir:  "../../templates",
		JWTPrivateKey: testJWTPrivateKey,
		JWTIssuer:     "http://localhost:8080",
	}
	emailSender := email.NewLogSender()
	s.server = New(config, s.datastore, emailSender)
	go s.server.Run()
	// Wait for the server to be listening before returning.
	for !s.server.IsListening() {
		time.Sleep(100 * time.Millisecond)
	}
	s.T().Logf("server is listening on %s", s.server.config.HTTPAddress)
}

func (s *OAuthFlowSuite) TearDownTest() {
	// Reset rate limits between tests to prevent rate limit errors
	s.server.ResetRateLimits()

	// Snapshot restoration between tests terminates database connections, breaking
	// the server's connection pool. Since each test uses unique random data and
	// doesn't conflict with others, we skip restoration here. If cleanup becomes
	// necessary, consider truncating specific tables instead.
}

func (s *OAuthFlowSuite) TearDownSuite() {
	s.NoError(s.server.Close())
	s.NoError(s.datastore.DB.Close())
}

// mustGenerateRandomString generates a random string of the given length.
func (s *OAuthFlowSuite) mustGenerateRandomString(length int) string {
	s.T().Helper()
	str, err := generateRandomString(length)
	s.Require().NoError(err)
	return str
}

func (s *OAuthFlowSuite) mustRegisterOAuthClient(params db.CreateOAuthClientParams) db.OauthClient {
	client, err := s.datastore.Q.CreateOAuthClient(s.T().Context(), params)
	s.Require().NoError(err)
	s.T().Logf("oauth client created: %s", client.ClientID)
	return client
}

func (s *OAuthFlowSuite) mustRegisterUser(username, password, email string) UserWithPassword {
	hashedPassword, err := auth.HashPassword(password)
	s.Require().NoError(err)
	authUser, err := s.datastore.Q.CreateUser(s.T().Context(), db.CreateUserParams{
		Username:     username,
		Email:        email,
		PasswordHash: hashedPassword,
	})
	s.Require().NoError(err)
	s.T().Logf("user created: %s", authUser.Username)
	return UserWithPassword{AuthUser: authUser, Password: password}
}

func (s *OAuthFlowSuite) mustEnableMFAForUser(user UserWithPassword, secret string) {
	// Enable MFA directly in the database
	err := s.datastore.Q.EnableMFA(s.T().Context(), db.EnableMFAParams{
		ID:        user.ID,
		MfaSecret: sql.NullString{String: secret, Valid: true},
	})
	s.Require().NoError(err)
	s.T().Logf("MFA enabled for user: %s", user.Username)
}

func (s *OAuthFlowSuite) mustCreateStateAndCodeVerifier() StateAndCodeVerifier {
	state := s.mustGenerateRandomString(32)
	codeVerifier := s.mustGenerateRandomString(32)
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])
	scv := StateAndCodeVerifier{
		State:               state,
		CodeVerifier:        codeVerifier,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: "S256",
	}
	s.T().Logf("state and code verifier created: %+v", scv)
	return scv
}

// mustCompleteOAuthFlow performs the full OAuth flow and returns the tokens.
// This helper enables tests to get tokens without duplicating the flow logic.
func (s *OAuthFlowSuite) mustCompleteOAuthFlow(clientParams db.CreateOAuthClientParams) OAuthFlowResult {
	s.T().Helper()

	client := s.mustRegisterOAuthClient(clientParams)
	user := s.mustRegisterUser(
		s.mustGenerateRandomString(8),
		s.mustGenerateRandomString(8),
		fmt.Sprintf("%s@example.com", s.mustGenerateRandomString(8)),
	)
	scv := s.mustCreateStateAndCodeVerifier()

	host := "localhost:8080"
	redirectURI := clientParams.RedirectUris[0]

	// Step 1: Login and get authorization code
	loginQuery := url.Values{
		"client_id":             {client.ClientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"code_challenge":        {scv.CodeChallenge},
		"code_challenge_method": {scv.CodeChallengeMethod},
		"state":                 {scv.State},
		"scope":                 {"openid profile email"},
	}
	formValues := url.Values{
		"username":              {user.Username},
		"password":              {user.Password},
		"client_id":             {client.ClientID},
		"redirect_uri":          {redirectURI},
		"state":                 {scv.State},
		"scope":                 {"openid profile email"},
		"code_challenge":        {scv.CodeChallenge},
		"code_challenge_method": {scv.CodeChallengeMethod},
	}
	postLoginUrl := fmt.Sprintf("http://%s/oauth/login?%s", host, loginQuery.Encode())
	resp, err := s.httpClient.PostForm(postLoginUrl, formValues)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode, "login should redirect")

	location := resp.Header.Get("Location")
	redirectUrl, err := url.ParseRequestURI(location)
	s.Require().NoError(err)
	authorizationCode := redirectUrl.Query().Get("code")
	s.Require().NotEmpty(authorizationCode, "should receive authorization code")

	// Step 2: Exchange authorization code for tokens
	tokenQuery := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authorizationCode},
		"redirect_uri":  {redirectURI},
		"client_id":     {client.ClientID},
		"code_verifier": {scv.CodeVerifier},
	}
	postTokenUrl := fmt.Sprintf("http://%s/oauth/token", host)
	resp, err = s.httpClient.PostForm(postTokenUrl, tokenQuery)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode, "token exchange should succeed")

	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	var tokenResponse TokenResponse
	err = json.Unmarshal(body, &tokenResponse)
	s.Require().NoError(err)

	return OAuthFlowResult{
		Client:        client,
		User:          user,
		TokenResponse: tokenResponse,
	}
}

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
		// Calling login should render the login page with the OAuth parameters preserved.

		// Call /login
		host := "localhost:8080"
		route := "/oauth/login"
		loginQuery := url.Values{
			"client_id":             {client.ClientID},
			"redirect_uri":          {clientCallbackURI},
			"response_type":         {"code"},
			"code_challenge":        {scv.CodeChallenge},
			"code_challenge_method": {scv.CodeChallengeMethod},
			"state":                 {scv.State},
			"scope":                 {"openid profile email"},
		}
		getLoginUrl := fmt.Sprintf("http://%s%s?%s", host, route, loginQuery.Encode())
		resp, err := s.httpClient.Get(getLoginUrl)
		s.Require().NoError(err)
		defer resp.Body.Close()
		s.Equal(http.StatusOK, resp.StatusCode)
		// Verify we get something that looks like the login page.
		body, err := io.ReadAll(resp.Body)
		s.Require().NoError(err)
		s.Contains(string(body), "Sign In")
		// Submit the login form.
		formValues := url.Values{
			// Login creds...
			"username": {user.Username},
			"password": {user.Password},
			// ...along with the original OAuth parameters.
			"client_id":             {client.ClientID},
			"redirect_uri":          {clientCallbackURI},
			"state":                 {scv.State},
			"scope":                 {"openid profile email"},
			"code_challenge":        {scv.CodeChallenge},
			"code_challenge_method": {scv.CodeChallengeMethod},
		}
		postLoginUrl := fmt.Sprintf("http://%s%s", host, route)
		resp, err = s.httpClient.PostForm(postLoginUrl, formValues)
		s.Require().NoError(err)
		defer resp.Body.Close()
		if !s.Equal(http.StatusFound, resp.StatusCode) {
			body, err := io.ReadAll(resp.Body)
			s.Require().NoError(err)
			s.T().Logf("response body: %s", string(body))
			s.FailNow("unexpected status code found")
		}
		// Verify it redirects to the callback URL with an authorization code.
		location := resp.Header.Get("Location")
		redirectUrl, err := url.ParseRequestURI(location)
		s.Require().NoError(err)
		s.Equal("localhost", redirectUrl.Hostname())
		s.Equal("8080", redirectUrl.Port())
		s.Equal("/callback", redirectUrl.Path)
		// Verify the authorization code is in the query parameters.
		authorizationCode = redirectUrl.Query().Get("code")
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
	s.True(userInfo.EmailVerified, "email_verified should be true")
}

// TestOAuthFlowWithMFA verifies that users with MFA enabled are redirected to the MFA page
// and can complete the flow by entering a valid TOTP code.
func (s *OAuthFlowSuite) TestOAuthFlowWithMFA() {
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

	// Generate a TOTP secret and enable MFA for the user
	totpKey, err := mfa.GenerateSecret(user.Username)
	s.Require().NoError(err)
	totpSecret := mfa.GetSecret(totpKey)
	s.mustEnableMFAForUser(user, totpSecret)

	scv := s.mustCreateStateAndCodeVerifier()
	host := "localhost:8080"

	// Step 1: Submit login - should redirect to MFA page instead of callback
	loginQuery := url.Values{
		"client_id":             {client.ClientID},
		"redirect_uri":          {clientCallbackURI},
		"response_type":         {"code"},
		"code_challenge":        {scv.CodeChallenge},
		"code_challenge_method": {scv.CodeChallengeMethod},
		"state":                 {scv.State},
		"scope":                 {"openid profile email"},
	}
	formValues := url.Values{
		"username":              {user.Username},
		"password":              {user.Password},
		"client_id":             {client.ClientID},
		"redirect_uri":          {clientCallbackURI},
		"state":                 {scv.State},
		"scope":                 {"openid profile email"},
		"code_challenge":        {scv.CodeChallenge},
		"code_challenge_method": {scv.CodeChallengeMethod},
	}
	postLoginUrl := fmt.Sprintf("http://%s/oauth/login?%s", host, loginQuery.Encode())
	resp, err := s.httpClient.PostForm(postLoginUrl, formValues)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode, "login should redirect")

	// Verify redirect is to MFA page, not callback
	location := resp.Header.Get("Location")
	s.Contains(location, "/oauth/mfa", "should redirect to MFA page")

	// Extract pending ID from redirect URL
	redirectUrl, err := url.ParseRequestURI(location)
	s.Require().NoError(err)
	pendingID := redirectUrl.Query().Get("pending")
	s.NotEmpty(pendingID, "should have pending ID")

	// Step 2: GET MFA page - should show form
	mfaPageUrl := fmt.Sprintf("http://%s%s", host, location)
	resp, err = s.httpClient.Get(mfaPageUrl)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	s.Contains(string(body), "Two-Factor Authentication")

	// Step 3: Submit valid MFA code - should redirect to callback with auth code
	// Generate a valid TOTP code
	validCode, err := generateTOTPCode(totpSecret)
	s.Require().NoError(err)

	mfaFormValues := url.Values{
		"pending_id": {pendingID},
		"code":       {validCode},
	}
	postMfaUrl := fmt.Sprintf("http://%s/oauth/mfa", host)
	resp, err = s.httpClient.PostForm(postMfaUrl, mfaFormValues)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode, "MFA verification should redirect")

	// Verify redirect is to callback with authorization code
	location = resp.Header.Get("Location")
	redirectUrl, err = url.ParseRequestURI(location)
	s.Require().NoError(err)
	s.Equal("/callback", redirectUrl.Path)
	authorizationCode := redirectUrl.Query().Get("code")
	s.NotEmpty(authorizationCode, "should receive authorization code")

	// Step 4: Exchange authorization code for tokens (verify flow completes)
	tokenQuery := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authorizationCode},
		"redirect_uri":  {clientCallbackURI},
		"client_id":     {client.ClientID},
		"code_verifier": {scv.CodeVerifier},
	}
	postTokenUrl := fmt.Sprintf("http://%s/oauth/token", host)
	resp, err = s.httpClient.PostForm(postTokenUrl, tokenQuery)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode, "token exchange should succeed")

	body, err = io.ReadAll(resp.Body)
	s.Require().NoError(err)
	var tokenResponse TokenResponse
	err = json.Unmarshal(body, &tokenResponse)
	s.Require().NoError(err)
	s.NotEmpty(tokenResponse.AccessToken)
}

// TestMFAWithInvalidCode verifies that an invalid MFA code is rejected.
func (s *OAuthFlowSuite) TestMFAWithInvalidCode() {
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

	// Generate a TOTP secret and enable MFA for the user
	totpKey, err := mfa.GenerateSecret(user.Username)
	s.Require().NoError(err)
	totpSecret := mfa.GetSecret(totpKey)
	s.mustEnableMFAForUser(user, totpSecret)

	scv := s.mustCreateStateAndCodeVerifier()
	host := "localhost:8080"

	// Submit login to get to MFA page
	formValues := url.Values{
		"username":              {user.Username},
		"password":              {user.Password},
		"client_id":             {client.ClientID},
		"redirect_uri":          {clientCallbackURI},
		"state":                 {scv.State},
		"scope":                 {"openid profile email"},
		"code_challenge":        {scv.CodeChallenge},
		"code_challenge_method": {scv.CodeChallengeMethod},
	}
	postLoginUrl := fmt.Sprintf("http://%s/oauth/login", host)
	resp, err := s.httpClient.PostForm(postLoginUrl, formValues)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)

	location := resp.Header.Get("Location")
	redirectUrl, err := url.ParseRequestURI(location)
	s.Require().NoError(err)
	pendingID := redirectUrl.Query().Get("pending")

	// Submit invalid MFA code
	mfaFormValues := url.Values{
		"pending_id": {pendingID},
		"code":       {"000000"}, // Invalid code
	}
	postMfaUrl := fmt.Sprintf("http://%s/oauth/mfa", host)
	resp, err = s.httpClient.PostForm(postMfaUrl, mfaFormValues)
	s.Require().NoError(err)
	defer resp.Body.Close()

	// Should return error page, not redirect
	s.Equal(http.StatusUnauthorized, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	s.Contains(string(body), "Invalid verification code")
}

// generateTOTPCode generates a valid TOTP code for the given secret.
// This uses the same library as the server to ensure compatibility.
func generateTOTPCode(secret string) (string, error) {
	// Use the pquerna/otp library to generate a code
	// We need to import it properly
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		return "", err
	}
	return code, nil
}

func prepareDatabase(t *testing.T) *postgres.PostgresContainer {
	t.Helper()

	// Create the test database container.
	pgContainer, err := postgres.Run(
		t.Context(),
		fmt.Sprintf("postgres:%s", testPgVersion),
		postgres.WithDatabase(testPgDatabase),
		postgres.WithUsername(testPgUser),
		postgres.WithPassword(testPgPassword),
		postgres.BasicWaitStrategies(),
		postgres.WithSQLDriver("pgx"),
	)
	assert.NoError(t, err)
	t.Logf("postgres container started: %s", pgContainer.GetContainerID())

	connStr, err := pgContainer.ConnectionString(t.Context(), "sslmode=disable")
	assert.NoError(t, err)

	// Run the migrations.
	absDir, err := filepath.Abs("../../db/migrations")
	assert.NoError(t, err)
	m, err := migrate.New(
		fmt.Sprintf("file://%s", absDir),
		connStr,
	)
	assert.NoError(t, err)

	assert.NoError(t, m.Up())
	t.Logf("migrations complete: %s", absDir)

	t.Cleanup(func() {
		_ = pgContainer.Terminate(t.Context())
	})

	// Take a snapshot that we can return to after each test.
	pgContainer.Snapshot(t.Context(), postgres.WithSnapshotName("post-migrations"))

	return pgContainer
}

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

	regResp, err := s.httpClient.PostForm("http://localhost:8080/oauth/register", url.Values{
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
	// Try to resend verification without being logged in
	resp, err := s.httpClient.Post("http://localhost:8080/oauth/resend-verification", "application/x-www-form-urlencoded", nil)
	s.Require().NoError(err)
	defer resp.Body.Close()

	// Should redirect to login
	s.Equal(http.StatusFound, resp.StatusCode)
	location := resp.Header.Get("Location")
	s.Contains(location, "/oauth/login")
}

// Password Reset Tests

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

	// Try login with new password (should succeed)
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
	s.Contains(resp.Header.Get("Location"), "code=")
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

// OIDC Discovery Tests

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

// Token Introspection Tests

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

	// Login and get authorization code
	formValues := url.Values{
		"username":              {user.Username},
		"password":              {user.Password},
		"client_id":             {tokenClient.ClientID},
		"redirect_uri":          {tokenClient.RedirectUris[0]},
		"state":                 {scv.State},
		"scope":                 {"openid profile email"},
		"code_challenge":        {scv.CodeChallenge},
		"code_challenge_method": {scv.CodeChallengeMethod},
	}
	resp, err := s.httpClient.PostForm("http://localhost:8080/oauth/login", formValues)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)

	location := resp.Header.Get("Location")
	redirectUrl, err := url.ParseRequestURI(location)
	s.Require().NoError(err)
	authCode := redirectUrl.Query().Get("code")

	// Exchange code for tokens
	tokenValues := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {tokenClient.RedirectUris[0]},
		"client_id":     {tokenClient.ClientID},
		"code_verifier": {scv.CodeVerifier},
	}
	resp, err = s.httpClient.PostForm("http://localhost:8080/oauth/token", tokenValues)
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

	formValues := url.Values{
		"username":              {user.Username},
		"password":              {user.Password},
		"client_id":             {tokenClient.ClientID},
		"redirect_uri":          {tokenClient.RedirectUris[0]},
		"state":                 {scv.State},
		"scope":                 {"openid profile email"},
		"code_challenge":        {scv.CodeChallenge},
		"code_challenge_method": {scv.CodeChallengeMethod},
	}
	resp, err := s.httpClient.PostForm("http://localhost:8080/oauth/login", formValues)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)

	location := resp.Header.Get("Location")
	redirectUrl, err := url.ParseRequestURI(location)
	s.Require().NoError(err)
	authCode := redirectUrl.Query().Get("code")

	tokenValues := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {tokenClient.RedirectUris[0]},
		"client_id":     {tokenClient.ClientID},
		"code_verifier": {scv.CodeVerifier},
	}
	resp, err = s.httpClient.PostForm("http://localhost:8080/oauth/token", tokenValues)
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

func TestOAuthFlowSuite(t *testing.T) {
	suite.Run(t, new(OAuthFlowSuite))
}
