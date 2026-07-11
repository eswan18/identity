//go:build integration

package httpserver

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eswan18/identity/pkg/auth"
	"github.com/eswan18/identity/pkg/config"
	"github.com/eswan18/identity/pkg/db"
	"github.com/eswan18/identity/pkg/email"
	"github.com/eswan18/identity/pkg/storage"
	"github.com/eswan18/identity/pkg/store"
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
	storageProvider := storage.NewLogStorage()
	s.server = New(config, s.datastore, emailSender, storageProvider)
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

// mustGenerateAlphanumericString generates a random alphanumeric string valid for usernames.
func (s *OAuthFlowSuite) mustGenerateAlphanumericString(length int) string {
	s.T().Helper()
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		// Use a simple modulo for test purposes (not cryptographically secure, but fine for tests)
		randBytes := make([]byte, 1)
		_, err := rand.Read(randBytes)
		s.Require().NoError(err)
		b[i] = charset[int(randBytes[0])%len(charset)]
	}
	return string(b)
}

// mustLoginAndConsent performs login, follows the redirect to authorize, approves consent,
// and returns the authorization code. Uses a cookie jar to maintain session.
func (s *OAuthFlowSuite) mustLoginAndConsent(user UserWithPassword, clientID, redirectURI, scope string, scv StateAndCodeVerifier) string {
	s.T().Helper()

	jar, err := cookiejar.New(nil)
	s.Require().NoError(err)
	httpClient := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Step 1: Login
	formValues := url.Values{
		"username":              {user.Username},
		"password":              {user.Password},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"state":                 {scv.State},
		"scope":                 {scope},
		"code_challenge":        {scv.CodeChallenge},
		"code_challenge_method": {scv.CodeChallengeMethod},
	}
	resp, err := httpClient.PostForm("http://localhost:8080/oauth/login", formValues)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode, "login should redirect")

	// Step 2: Follow redirect to /oauth/authorize → /oauth/consent
	authorizeURL := resp.Header.Get("Location")
	if !strings.HasPrefix(authorizeURL, "http") {
		authorizeURL = "http://localhost:8080" + authorizeURL
	}
	resp, err = httpClient.Get(authorizeURL)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode, "authorize should redirect to consent")

	// Step 3: Approve consent
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
	resp, err = httpClient.PostForm("http://localhost:8080/oauth/consent", consentForm)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode, "consent should redirect to client")

	location := resp.Header.Get("Location")
	redirectUrl, err := url.ParseRequestURI(location)
	s.Require().NoError(err)
	code := redirectUrl.Query().Get("code")
	s.Require().NotEmpty(code, "should receive authorization code")
	return code
}

func (s *OAuthFlowSuite) mustRegisterOAuthClient(params db.CreateOAuthClientParams) db.OauthClient {
	// The server stores only a hash of the client secret, so hash it before
	// insert. Preserve the plaintext on the returned struct so callers can
	// still present it when authenticating.
	plaintextSecret := params.ClientSecret
	if params.ClientSecret.Valid {
		params.ClientSecret = sql.NullString{String: auth.HashClientSecret(params.ClientSecret.String), Valid: true}
	}
	client, err := s.datastore.Q.CreateOAuthClient(s.T().Context(), params)
	s.Require().NoError(err)
	client.ClientSecret = plaintextSecret
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
	scv := StateAndCodeVerifier{
		State:               state,
		CodeVerifier:        codeVerifier,
		CodeChallenge:       generateCodeChallenge(codeVerifier),
		CodeChallengeMethod: "S256",
	}
	s.T().Logf("state and code verifier created: %+v", scv)
	return scv
}

// mustCompleteOAuthFlow performs the full OAuth flow and returns the tokens.
// This helper enables tests to get tokens without duplicating the flow logic.
// mustCompleteOAuthFlow completes a full OAuth flow and returns the result.
// An optional scope string can be passed; if omitted, defaults to "openid profile email".
func (s *OAuthFlowSuite) mustCompleteOAuthFlow(clientParams db.CreateOAuthClientParams, scopeOverride ...string) OAuthFlowResult {
	s.T().Helper()

	scope := "openid profile email"
	if len(scopeOverride) > 0 {
		scope = scopeOverride[0]
	}

	client := s.mustRegisterOAuthClient(clientParams)
	user := s.mustRegisterUser(
		s.mustGenerateRandomString(8),
		s.mustGenerateRandomString(8),
		fmt.Sprintf("%s@example.com", s.mustGenerateRandomString(8)),
	)
	scv := s.mustCreateStateAndCodeVerifier()

	host := "localhost:8080"
	redirectURI := clientParams.RedirectUris[0]

	// Use a cookie jar client to maintain session across login → authorize → consent
	jar, err := cookiejar.New(nil)
	s.Require().NoError(err)
	httpClient := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Step 1: Login (establishes session, redirects to /oauth/authorize)
	formValues := url.Values{
		"username":              {user.Username},
		"password":              {user.Password},
		"client_id":             {client.ClientID},
		"redirect_uri":          {redirectURI},
		"state":                 {scv.State},
		"scope":                 {scope},
		"code_challenge":        {scv.CodeChallenge},
		"code_challenge_method": {scv.CodeChallengeMethod},
	}
	postLoginUrl := fmt.Sprintf("http://%s/oauth/login", host)
	resp, err := httpClient.PostForm(postLoginUrl, formValues)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode, "login should redirect")

	// Step 2: Follow redirect to /oauth/authorize (redirects to /oauth/consent)
	authorizeURL := resp.Header.Get("Location")
	if !strings.HasPrefix(authorizeURL, "http") {
		authorizeURL = fmt.Sprintf("http://%s%s", host, authorizeURL)
	}
	resp, err = httpClient.Get(authorizeURL)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode, "authorize should redirect to consent")

	// Step 3: Approve consent (redirects to client with code)
	consentLocation := resp.Header.Get("Location")
	consentURL, err := url.Parse(consentLocation)
	s.Require().NoError(err)
	consentFormValues := url.Values{
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
	postConsentUrl := fmt.Sprintf("http://%s/oauth/consent", host)
	resp, err = httpClient.PostForm(postConsentUrl, consentFormValues)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode, "consent should redirect to client")

	location := resp.Header.Get("Location")
	redirectUrl, err := url.ParseRequestURI(location)
	s.Require().NoError(err)
	authorizationCode := redirectUrl.Query().Get("code")
	s.Require().NotEmpty(authorizationCode, "should receive authorization code")

	// Step 4: Exchange authorization code for tokens
	tokenQuery := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authorizationCode},
		"redirect_uri":  {redirectURI},
		"client_id":     {client.ClientID},
		"code_verifier": {scv.CodeVerifier},
	}
	postTokenUrl := fmt.Sprintf("http://%s/oauth/token", host)
	resp, err = httpClient.PostForm(postTokenUrl, tokenQuery)
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

// mustLoginAndGetAuthorizeClient is a helper that creates a user, logs in to get a session,
// and returns an HTTP client with the session cookie and the registered OAuth client.
func (s *OAuthFlowSuite) mustLoginAndGetAuthorizeClient(clientParams db.CreateOAuthClientParams) (*http.Client, db.OauthClient) {
	s.T().Helper()
	client := s.mustRegisterOAuthClient(clientParams)
	username := s.mustGenerateRandomString(8)
	password := s.mustGenerateRandomString(16)
	s.mustRegisterUser(username, password, fmt.Sprintf("%s@example.com", username))

	jar, err := cookiejar.New(nil)
	s.Require().NoError(err)
	httpClient := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Login to establish a session
	resp, err := httpClient.PostForm("http://localhost:8080/oauth/login", url.Values{
		"username": {username},
		"password": {password},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)

	return httpClient, client
}

// Helper function to get a client credentials token
func (s *OAuthFlowSuite) mustGetClientCredentialsToken(clientID, clientSecret, scope string) string {
	tokenValues := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"scope":         {scope},
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

	return tokenResponse.AccessToken
}

// Helper function to create a user via admin API
func (s *OAuthFlowSuite) mustCreateUserViaAdminAPI(token, username, email, password string) CreateUserResponse {
	createUserReq := CreateUserRequest{
		Username: username,
		Email:    email,
		Password: password,
	}
	reqBody, err := json.Marshal(createUserReq)
	s.Require().NoError(err)

	req, err := http.NewRequest("POST", "http://localhost:8080/admin/users", strings.NewReader(string(reqBody)))
	s.Require().NoError(err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := s.httpClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusCreated, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	var createUserResp CreateUserResponse
	err = json.Unmarshal(body, &createUserResp)
	s.Require().NoError(err)

	return createUserResp
}

func TestOAuthFlowSuite(t *testing.T) {
	suite.Run(t, new(OAuthFlowSuite))
}

// generateCodeChallenge returns the S256 PKCE code challenge for a verifier.
func generateCodeChallenge(codeVerifier string) string {
	hash := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
