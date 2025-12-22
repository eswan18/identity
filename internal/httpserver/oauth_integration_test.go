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

type UserWithPassword struct {
	db.AuthUser
	Password string
}

func mustGenerateRandomString(t *testing.T, length int) string {
	t.Helper()
	s, err := generateRandomString(length)
	assert.NoError(t, err)
	return s
}

func TestOAuthIntegration(t *testing.T) {
	assert := assert.New(t)

	_, dbURL := prepareDatabase(t)
	datastore, err := store.New(dbURL)
	assert.NoError(err)
	defer datastore.DB.Close()

	config := &config.Config{HTTPAddress: ":8080", TemplatesDir: "../../templates"}
	server := New(config, datastore)
	go server.Run()
	defer server.Close()

	var client db.OauthClient
	{
		clientID := mustGenerateRandomString(t, 8)
		name := mustGenerateRandomString(t, 8)
		client, err = datastore.Q.CreateOAuthClient(t.Context(), db.CreateOAuthClientParams{
			ClientID:       clientID,
			ClientSecret:   sql.NullString{String: "", Valid: false},
			Name:           name,
			RedirectUris:   []string{"http://localhost:8080/callback"},
			AllowedScopes:  []string{"openid", "profile", "email"},
			IsConfidential: false,
		})
		assert.NoError(err)
		t.Logf("oauth client created: %s", client.ClientID)
	}

	// Register a user in the database.
	var user UserWithPassword
	{
		username := mustGenerateRandomString(t, 8)
		password := mustGenerateRandomString(t, 8)
		hashedPassword, err := auth.HashPassword(password)
		assert.NoError(err)
		authUser, err := datastore.Q.CreateUser(t.Context(), db.CreateUserParams{
			Username:     username,
			Email:        mustGenerateRandomString(t, 8),
			PasswordHash: hashedPassword,
		})
		assert.NoError(err)
		user = UserWithPassword{
			AuthUser: authUser,
			Password: password,
		}
	}

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
		state := mustGenerateRandomString(t, 32)
		query := url.Values{
			"client_id":             {client.ClientID},
			"redirect_uri":          {"http://localhost:8080/callback"},
			"response_type":         {"code"},
			"code_challenge":        {"abc"},
			"code_challenge_method": {"S256"},
			"state":                 {state},
			"scope":                 {"openid profile email"},
		}
		authorizeUrl := fmt.Sprintf("http://%s%s?%s", host, route, query.Encode())
		resp, err := httpClient.Get(authorizeUrl)
		assert.NoError(err)
		defer resp.Body.Close()
		assert.Equal(http.StatusFound, resp.StatusCode)
		// Verify it redirects to the login page
		location := resp.Header.Get("Location")
		redirectUrl, err := url.ParseRequestURI(location)
		assert.NoError(err)
		// We should be redirected to the login page with the OAuth parameters preserved.
		assert.Equal("/oauth/login", redirectUrl.Path)
		assert.Equal(query, redirectUrl.Query())
	})

	// Generate a code verifier and code challenge for PKCE.
	codeVerifier := mustGenerateRandomString(t, 32)
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])
	codeChallengeMethod := "S256"
	// Generate a random state for CSRF protection.
	state := mustGenerateRandomString(t, 32)
	// Create a variable to store the returned authorization code.
	var authorizationCode string
	t.Run("/oauth/login", func(t *testing.T) {
		// Calling login should render the login page with the OAuth parameters preserved.

		// Call /login
		host := "localhost:8080"
		route := "/oauth/login"
		loginQuery := url.Values{
			"client_id":             {client.ClientID},
			"redirect_uri":          {"http://localhost:8080/callback"},
			"response_type":         {"code"},
			"code_challenge":        {codeChallenge},
			"code_challenge_method": {codeChallengeMethod},
			"state":                 {state},
			"scope":                 {"openid profile email"},
		}
		loginUrl := fmt.Sprintf("http://%s%s?%s", host, route, loginQuery.Encode())
		resp, err := httpClient.Get(loginUrl)
		assert.NoError(err)
		defer resp.Body.Close()
		assert.Equal(http.StatusOK, resp.StatusCode)
		// Verify we get something that looks like the login page.
		body, err := io.ReadAll(resp.Body)
		assert.NoError(err)
		assert.Contains(string(body), "login")
		// Then submit the login form.
		formValues := url.Values{
			"username": {user.Username},
			"password": {user.Password},
		}
		// Add in the OAuth parameters.
		for key, values := range loginQuery {
			for _, value := range values {
				formValues.Add(key, value)
			}
		}
		resp, err = httpClient.PostForm(loginUrl, formValues)
		assert.NoError(err)
		defer resp.Body.Close()
		if !assert.Equal(http.StatusFound, resp.StatusCode) {
			body, err := io.ReadAll(resp.Body)
			assert.NoError(err)
			t.Logf("response body: %s", string(body))
			assert.FailNow("unexpected status found")
		}
		// Verify it redirects to the callback URL with an authorization code.
		location := resp.Header.Get("Location")
		redirectUrl, err := url.ParseRequestURI(location)
		assert.NoError(err)
		assert.Equal("localhost", redirectUrl.Hostname())
		assert.Equal("8080", redirectUrl.Port())
		assert.Equal("/callback", redirectUrl.Path)
		// Verify the authorization code is in the query parameters.
		authorizationCode = redirectUrl.Query().Get("code")
		assert.NotEmpty(authorizationCode)
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
			"client_id":     {client.ClientID},
			"code_verifier": {codeVerifier},
		}
		tokenUrl := fmt.Sprintf("http://%s%s?%s", host, route, tokenQuery.Encode())
		resp, err := httpClient.PostForm(tokenUrl, tokenQuery)
		assert.NoError(err)
		defer resp.Body.Close()
		if !assert.Equal(http.StatusOK, resp.StatusCode) {
			body, err := io.ReadAll(resp.Body)
			assert.NoError(err)
			t.Logf("response body: %s", string(body))
		}
		body, err := io.ReadAll(resp.Body)
		assert.NoError(err)
		err = json.Unmarshal(body, &tokenResponse)
		assert.NoError(err)
		assert.NotEmpty(tokenResponse.AccessToken)
		assert.Equal("Bearer", tokenResponse.TokenType)
		assert.Greater(tokenResponse.ExpiresIn, 0)
		assert.NotEmpty(tokenResponse.RefreshToken)
		assert.Equal("openid profile email", tokenResponse.Scope)
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
			"client_id":     {client.ClientID},
		}
		refreshUrl := fmt.Sprintf("http://%s%s?%s", host, route, refreshQuery.Encode())
		resp, err := httpClient.PostForm(refreshUrl, refreshQuery)
		assert.NoError(err)
		defer resp.Body.Close()
		assert.Equal(http.StatusOK, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		assert.NoError(err)
		err = json.Unmarshal(body, &tokenResponse)
		assert.NoError(err)
		assert.NotEmpty(tokenResponse.AccessToken)
		assert.Equal("Bearer", tokenResponse.TokenType)
		assert.Greater(tokenResponse.ExpiresIn, 0)
		assert.NotEmpty(tokenResponse.RefreshToken)
		assert.Equal("openid profile email", tokenResponse.Scope)
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
