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

	"github.com/eswan18/identity/internal/auth"
	"github.com/eswan18/identity/internal/config"
	"github.com/eswan18/identity/internal/db"
	"github.com/eswan18/identity/internal/store"
	"github.com/stretchr/testify/assert"
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

func TestOAuthIntegration(t *testing.T) {
	_, dbURL := prepareDatabase(t)
	datastore, err := store.New(dbURL)
	assert.NoError(t, err)
	defer datastore.DB.Close()

	config := &config.Config{HTTPAddress: ":8080", TemplatesDir: "../../templates"}
	server := New(config, datastore)
	go server.Run()
	defer server.Close()

	// Register an oauth client in the database.
	clientID, err := generateRandomString(8)
	assert.NoError(t, err)
	clientSecret, err := generateRandomString(32)
	assert.NoError(t, err)
	client, err := datastore.Q.CreateOAuthClient(t.Context(), db.CreateOAuthClientParams{
		ClientID:       clientID,
		ClientSecret:   sql.NullString{String: clientSecret, Valid: true},
		Name:           "test-client",
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid", "profile", "email"},
		IsConfidential: false,
	})
	assert.NoError(t, err)
	t.Logf("oauth client created: %s", client.ClientID)

	// Register a user in the database.
	username := "testuser"
	password := "testpassword"
	hashedPassword, err := auth.HashPassword(password)
	assert.NoError(t, err)
	user, err := datastore.Q.CreateUser(t.Context(), db.CreateUserParams{
		Username:     username,
		Email:        "testuser@example.com",
		PasswordHash: hashedPassword,
	})
	assert.NoError(t, err)
	t.Logf("user created: %s", user.Username)

	// Make an http client that doesn't follow redirects so we can check the 302 status
	httpClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	t.Run("/oauth/authorize", func(t *testing.T) {
		// Calling authorize should redirect to the login page with the OAuth parameters preserved.

		// Call /authorize
		host := "localhost:8080"
		route := "/oauth/authorize"
		state, err := generateRandomString(32)
		assert.NoError(t, err)
		query := url.Values{
			"client_id":             {clientID},
			"redirect_uri":          {"http://localhost:8080/callback"},
			"response_type":         {"code"},
			"code_challenge":        {"abc"},
			"code_challenge_method": {"S256"},
			"state":                 {state},
			"scope":                 {"openid profile email"},
		}
		authorizeUrl := fmt.Sprintf("http://%s%s?%s", host, route, query.Encode())
		resp, err := httpClient.Get(authorizeUrl)
		assert.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusFound, resp.StatusCode)
		// Verify it redirects to the login page
		location := resp.Header.Get("Location")
		redirectUrl, err := url.ParseRequestURI(location)
		assert.NoError(t, err)
		// We should be redirected to the login page with the OAuth parameters preserved.
		assert.Equal(t, "/oauth/login", redirectUrl.Path)
		assert.Equal(t, query, redirectUrl.Query())
	})

	// Generate a code verifier and code challenge for PKCE.
	codeVerifier, err := generateRandomString(32)
	assert.NoError(t, err)
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])
	codeChallengeMethod := "S256"
	// Generate a random state for CSRF protection.
	state, err := generateRandomString(32)
	assert.NoError(t, err)
	// Create a variable to store the returned authorization code.
	var authorizationCode string
	t.Run("/oauth/login", func(t *testing.T) {
		// Calling login should render the login page with the OAuth parameters preserved.

		// Call /login
		host := "localhost:8080"
		route := "/oauth/login"
		loginQuery := url.Values{
			"client_id":             {clientID},
			"redirect_uri":          {"http://localhost:8080/callback"},
			"response_type":         {"code"},
			"code_challenge":        {codeChallenge},
			"code_challenge_method": {codeChallengeMethod},
			"state":                 {state},
			"scope":                 {"openid profile email"},
		}
		loginUrl := fmt.Sprintf("http://%s%s?%s", host, route, loginQuery.Encode())
		resp, err := httpClient.Get(loginUrl)
		assert.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		// Verify we get something that looks like the login page.
		body, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Contains(t, string(body), "login")
		// Then submit the login form.
		formValues := url.Values{
			"username": {username},
			"password": {password},
		}
		// Add in the OAuth parameters.
		for key, values := range loginQuery {
			for _, value := range values {
				formValues.Add(key, value)
			}
		}
		resp, err = httpClient.PostForm(loginUrl, formValues)
		assert.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusFound, resp.StatusCode)
		// Verify it redirects to the callback URL with an authorization code.
		location := resp.Header.Get("Location")
		redirectUrl, err := url.ParseRequestURI(location)
		assert.NoError(t, err)
		assert.Equal(t, "localhost", redirectUrl.Hostname())
		assert.Equal(t, "8080", redirectUrl.Port())
		assert.Equal(t, "/callback", redirectUrl.Path)
		// Verify the authorization code is in the query parameters.
		authorizationCode = redirectUrl.Query().Get("code")
		assert.NotEmpty(t, authorizationCode)
	})

	var tokenResponse TokenResponse
	t.Run("/oauth/token", func(t *testing.T) {
		// Calling token should exchange the authorization code for a token.

		// Call /token
		host := "localhost:8080"
		route := "/oauth/token"
		tokenQuery := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {authorizationCode},
			"redirect_uri":  {"http://localhost:8080/callback"},
			"client_id":     {clientID},
			"client_secret": {clientSecret},
			"code_verifier": {codeVerifier},
		}
		tokenUrl := fmt.Sprintf("http://%s%s?%s", host, route, tokenQuery.Encode())
		resp, err := httpClient.PostForm(tokenUrl, tokenQuery)
		assert.NoError(t, err)
		defer resp.Body.Close()
		if !assert.Equal(t, http.StatusOK, resp.StatusCode) {
			body, err := io.ReadAll(resp.Body)
			assert.NoError(t, err)
			t.Logf("response body: %s", string(body))
		}
		body, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		err = json.Unmarshal(body, &tokenResponse)
		assert.NoError(t, err)
		assert.NotEmpty(t, tokenResponse.AccessToken)
		assert.Equal(t, "Bearer", tokenResponse.TokenType)
		assert.Greater(t, tokenResponse.ExpiresIn, 0)
		assert.NotEmpty(t, tokenResponse.RefreshToken)
		assert.Equal(t, "openid profile email", tokenResponse.Scope)
	})

	t.Run("/oauth/refresh", func(t *testing.T) {
		// Calling refresh should exchange the refresh token for a new token.
		t.Skip("Not implemented yet")

		// Call /refresh
		host := "localhost:8080"
		route := "/oauth/refresh"
		refreshQuery := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {tokenResponse.RefreshToken},
			"client_id":     {clientID},
			"client_secret": {clientSecret},
		}
		refreshUrl := fmt.Sprintf("http://%s%s?%s", host, route, refreshQuery.Encode())
		resp, err := httpClient.PostForm(refreshUrl, refreshQuery)
		assert.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		err = json.Unmarshal(body, &tokenResponse)
		assert.NoError(t, err)
		assert.NotEmpty(t, tokenResponse.AccessToken)
		assert.Equal(t, "Bearer", tokenResponse.TokenType)
		assert.Greater(t, tokenResponse.ExpiresIn, 0)
		assert.NotEmpty(t, tokenResponse.RefreshToken)
		assert.Equal(t, "openid profile email", tokenResponse.Scope)
	})
}

func prepareDatabase(t *testing.T) (*postgres.PostgresContainer, string) {
	t.Helper()

	// Create the test database container.
	pgContainer, err := postgres.Run(
		t.Context(),
		fmt.Sprintf("postgres:%s", testPgVersion),
		postgres.WithDatabase(testPgDatabase),
		postgres.WithUsername(testPgUser),
		postgres.WithPassword(testPgPassword),
		postgres.BasicWaitStrategies(),
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

	// Todo: run migrations
	return pgContainer, connStr
}
