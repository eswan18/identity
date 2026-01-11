// /* //go:build integration */

package httpserver

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/eswan18/identity/pkg/auth"
	"github.com/eswan18/identity/pkg/config"
	"github.com/eswan18/identity/pkg/db"
	"github.com/eswan18/identity/pkg/store"
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
	s.server = New(config, s.datastore)
	go s.server.Run()
	// Wait for the server to be listening before returning.
	for !s.server.IsListening() {
		time.Sleep(100 * time.Millisecond)
	}
	s.T().Logf("server is listening on %s", s.server.config.HTTPAddress)
}

func (s *OAuthFlowSuite) TearDownTest() {
	// Return to the snapshot of the DB from before any tests ran.
	s.pgContainer.Restore(s.T().Context(), postgres.WithSnapshotName("post-migrations"))
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

func (s *OAuthFlowSuite) TestOAuthIntegrationForNonconfidentialClient() {
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

func TestOAuthFlowSuite(t *testing.T) {
	suite.Run(t, new(OAuthFlowSuite))
}
