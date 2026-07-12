//go:build integration

package httpserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"image"
	"image/color"
	"image/jpeg"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eswan18/identity/pkg/auth"
	"github.com/eswan18/identity/pkg/config"
	"github.com/eswan18/identity/pkg/db"
	"github.com/eswan18/identity/pkg/email"
	"github.com/eswan18/identity/pkg/storage"
	"github.com/eswan18/identity/pkg/store"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go/modules/minio"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

const (
	minioUser     = "minioadmin"
	minioPassword = "minioadmin"
	minioBucket   = "avatars"
)

type AvatarFlowSuite struct {
	suite.Suite
	httpClient     *http.Client
	pgContainer    *postgres.PostgresContainer
	minioContainer *minio.MinioContainer
	datastore      *store.Store
	server         *Server
	storageService storage.Storage
}

func (s *AvatarFlowSuite) SetupSuite() {
	ctx := context.Background()
	var err error

	// Setup HTTP client that doesn't follow redirects (for testing redirect flows)
	s.httpClient = &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Setup PostgreSQL container
	s.pgContainer = prepareDatabase(s.T())
	dbURL, err := s.pgContainer.ConnectionString(s.T().Context(), "sslmode=disable")
	s.NoError(err)
	s.datastore, err = store.New(dbURL)
	s.NoError(err)

	// Setup MinIO container
	s.minioContainer, err = minio.Run(ctx,
		"minio/minio:latest",
		minio.WithUsername(minioUser),
		minio.WithPassword(minioPassword),
	)
	s.Require().NoError(err)

	// Get MinIO connection details
	minioEndpoint, err := s.minioContainer.ConnectionString(ctx)
	s.Require().NoError(err)

	// Create S3-compatible storage pointing to MinIO
	// The storage package will create the bucket if it doesn't exist
	s.storageService, err = storage.NewS3Storage(
		"http://"+minioEndpoint,
		minioBucket,
		minioUser,
		minioPassword,
		"http://"+minioEndpoint+"/"+minioBucket, // Public URL
		"us-east-1", // MinIO default region
	)
	s.Require().NoError(err)

	// Create bucket using the storage service helper
	err = s.storageService.(*storage.S3Storage).CreateBucket(ctx)
	s.Require().NoError(err)

	// Grant anonymous read access so tests can fetch uploaded avatars by their
	// public URL, mirroring the public bucket/CDN used in production.
	err = s.storageService.(*storage.S3Storage).MakeBucketPublicRead(ctx)
	s.Require().NoError(err)

	// Setup server
	cfg := &config.Config{
		HTTPAddress:   ":8081", // Use different port than OAuthFlowSuite
		JWTPrivateKey: testJWTPrivateKey,
		JWTIssuer:     "http://localhost:8081",
	}
	emailSender := email.NewLogSender()
	s.server = New(cfg, s.datastore, emailSender, s.storageService)
	go s.server.Run()

	// Wait for the server to be listening before returning
	for !s.server.IsListening() {
		time.Sleep(100 * time.Millisecond)
	}
	s.T().Logf("avatar test server is listening on %s", s.server.config.HTTPAddress)
}

func (s *AvatarFlowSuite) TearDownTest() {
	s.server.ResetRateLimits()
}

func (s *AvatarFlowSuite) TearDownSuite() {
	ctx := context.Background()
	s.NoError(s.server.Close())
	s.NoError(s.datastore.DB.Close())
	if s.pgContainer != nil {
		s.NoError(s.pgContainer.Terminate(ctx))
	}
	if s.minioContainer != nil {
		s.NoError(s.minioContainer.Terminate(ctx))
	}
}

// createTestJPEG creates a minimal valid JPEG image
func createTestJPEG(width, height int) ([]byte, error) {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	// Fill with a solid color
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.RGBA{R: 100, G: 150, B: 200, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 85}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// loginAndGetClient logs in as the given user and returns an HTTP client with session cookie
func (s *AvatarFlowSuite) loginAndGetClient(user db.AuthUser, password string) *http.Client {
	jar, err := cookiejar.New(nil)
	s.Require().NoError(err)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Seed the CSRF token/cookie from the login page (double-submit). The cookie has
	// Path=/ and stays in the jar, so every later request from this client (including
	// the multipart avatar uploads and the delete-avatar POST) carries it; those
	// requests only need to add the matching csrf_token form field.
	loginURL := "http://localhost:8081/oauth/login"
	csrfToken, _ := fetchCSRFToken(s.T(), client, loginURL)

	// Post to login form
	form := url.Values{}
	form.Set("username", user.Username)
	form.Set("password", password)
	form.Set("csrf_token", csrfToken)
	resp, err := client.PostForm(loginURL, form)
	s.Require().NoError(err)
	defer resp.Body.Close()

	// Should redirect on successful login
	s.Require().Equal(http.StatusFound, resp.StatusCode)

	return client
}

// csrfTokenFromJar returns the csrf_token cookie value currently held in the client's
// cookie jar (seeded by loginAndGetClient). Used to populate the csrf_token field on
// multipart avatar uploads, where the cookie itself is sent automatically by the jar.
func (s *AvatarFlowSuite) csrfTokenFromJar(client *http.Client) string {
	u, err := url.Parse("http://localhost:8081/")
	s.Require().NoError(err)
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == csrfCookieName {
			return c.Value
		}
	}
	s.Require().FailNow("no csrf_token cookie present in jar")
	return ""
}

func (s *AvatarFlowSuite) TestAvatarUpload() {
	// Create a test user
	user, password := s.mustRegisterUser()

	// Login and get authenticated client
	client := s.loginAndGetClient(user, password)

	// Create a test JPEG image
	imgData, err := createTestJPEG(512, 512)
	s.Require().NoError(err)

	// Create multipart form
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("avatar", "test.jpg")
	s.Require().NoError(err)
	_, err = io.Copy(part, bytes.NewReader(imgData))
	s.Require().NoError(err)
	s.Require().NoError(writer.WriteField("csrf_token", s.csrfTokenFromJar(client)))
	s.Require().NoError(writer.Close())

	// POST to change-avatar
	req, err := http.NewRequest("POST", "http://localhost:8081/oauth/change-avatar", body)
	s.Require().NoError(err)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp, err := client.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()

	// Should return OK with success message
	s.Require().Equal(http.StatusOK, resp.StatusCode)

	// Verify user has picture URL in database
	updatedUser, err := s.datastore.Q.GetUserByID(s.T().Context(), user.ID)
	s.Require().NoError(err)
	s.Require().True(updatedUser.Picture.Valid)
	s.Require().NotEmpty(updatedUser.Picture.String)
	s.Require().Contains(updatedUser.Picture.String, minioBucket)
}

func (s *AvatarFlowSuite) TestAvatarUploadOversizedFile() {
	// Create a test user
	user, password := s.mustRegisterUser()

	// Login and get authenticated client
	client := s.loginAndGetClient(user, password)

	// Create a large "file" (just bytes, not a real image)
	// 6MB is over the 5MB limit
	largeData := make([]byte, 6*1024*1024)

	// Create multipart form
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("avatar", "large.jpg")
	s.Require().NoError(err)
	_, err = io.Copy(part, bytes.NewReader(largeData))
	s.Require().NoError(err)
	s.Require().NoError(writer.WriteField("csrf_token", s.csrfTokenFromJar(client)))
	s.Require().NoError(writer.Close())

	// POST to change-avatar
	req, err := http.NewRequest("POST", "http://localhost:8081/oauth/change-avatar", body)
	s.Require().NoError(err)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp, err := client.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()

	// Should return OK but with error in page (form re-rendered with error)
	s.Require().Equal(http.StatusOK, resp.StatusCode)

	// Verify user still has no picture
	updatedUser, err := s.datastore.Q.GetUserByID(s.T().Context(), user.ID)
	s.Require().NoError(err)
	s.Require().False(updatedUser.Picture.Valid)
}

func (s *AvatarFlowSuite) TestAvatarUploadInvalidFileType() {
	// Create a test user
	user, password := s.mustRegisterUser()

	// Login and get authenticated client
	client := s.loginAndGetClient(user, password)

	// Create a text file (invalid type)
	textData := []byte("this is not an image")

	// Create multipart form
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("avatar", "test.txt")
	s.Require().NoError(err)
	_, err = io.Copy(part, bytes.NewReader(textData))
	s.Require().NoError(err)
	s.Require().NoError(writer.WriteField("csrf_token", s.csrfTokenFromJar(client)))
	s.Require().NoError(writer.Close())

	// POST to change-avatar
	req, err := http.NewRequest("POST", "http://localhost:8081/oauth/change-avatar", body)
	s.Require().NoError(err)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp, err := client.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()

	// Should return OK but with error in page
	s.Require().Equal(http.StatusOK, resp.StatusCode)

	// Verify user still has no picture
	updatedUser, err := s.datastore.Q.GetUserByID(s.T().Context(), user.ID)
	s.Require().NoError(err)
	s.Require().False(updatedUser.Picture.Valid)
}

func (s *AvatarFlowSuite) TestAvatarUpdate() {
	// Test that updating an existing avatar works correctly
	// (regression test for bug where delete after upload removed the new file)

	// Create a test user
	user, password := s.mustRegisterUser()

	// Login and get authenticated client
	client := s.loginAndGetClient(user, password)

	// Upload first avatar
	imgData1, err := createTestJPEG(256, 256)
	s.Require().NoError(err)

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("avatar", "first.jpg")
	s.Require().NoError(err)
	_, err = io.Copy(part, bytes.NewReader(imgData1))
	s.Require().NoError(err)
	s.Require().NoError(writer.WriteField("csrf_token", s.csrfTokenFromJar(client)))
	s.Require().NoError(writer.Close())

	req, err := http.NewRequest("POST", "http://localhost:8081/oauth/change-avatar", body)
	s.Require().NoError(err)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp, err := client.Do(req)
	s.Require().NoError(err)
	resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)

	// Verify first avatar was uploaded
	updatedUser, err := s.datastore.Q.GetUserByID(s.T().Context(), user.ID)
	s.Require().NoError(err)
	s.Require().True(updatedUser.Picture.Valid)
	firstURL := updatedUser.Picture.String

	// Upload second avatar (update)
	imgData2, err := createTestJPEG(512, 512) // Different size to ensure it's a new image
	s.Require().NoError(err)

	body = &bytes.Buffer{}
	writer = multipart.NewWriter(body)
	part, err = writer.CreateFormFile("avatar", "second.jpg")
	s.Require().NoError(err)
	_, err = io.Copy(part, bytes.NewReader(imgData2))
	s.Require().NoError(err)
	s.Require().NoError(writer.WriteField("csrf_token", s.csrfTokenFromJar(client)))
	s.Require().NoError(writer.Close())

	req, err = http.NewRequest("POST", "http://localhost:8081/oauth/change-avatar", body)
	s.Require().NoError(err)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp, err = client.Do(req)
	s.Require().NoError(err)
	resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)

	// Verify second avatar is now set
	updatedUser, err = s.datastore.Q.GetUserByID(s.T().Context(), user.ID)
	s.Require().NoError(err)
	s.Require().True(updatedUser.Picture.Valid, "Picture should still be valid after update")
	s.Require().NotEmpty(updatedUser.Picture.String, "Picture URL should not be empty after update")

	// URL should be the same since we use the same key
	s.Require().Equal(firstURL, updatedUser.Picture.String)

	// Verify the file is actually accessible (not deleted)
	imgResp, err := http.Get(updatedUser.Picture.String)
	s.Require().NoError(err)
	defer imgResp.Body.Close()
	s.Require().Equal(http.StatusOK, imgResp.StatusCode, "Avatar image should be accessible after update")
}

func (s *AvatarFlowSuite) TestAvatarDelete() {
	// Create a test user
	user, password := s.mustRegisterUser()

	// Login and get authenticated client
	client := s.loginAndGetClient(user, password)

	// First upload an avatar
	imgData, err := createTestJPEG(256, 256)
	s.Require().NoError(err)

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("avatar", "test.jpg")
	s.Require().NoError(err)
	_, err = io.Copy(part, bytes.NewReader(imgData))
	s.Require().NoError(err)
	s.Require().NoError(writer.WriteField("csrf_token", s.csrfTokenFromJar(client)))
	s.Require().NoError(writer.Close())

	req, err := http.NewRequest("POST", "http://localhost:8081/oauth/change-avatar", body)
	s.Require().NoError(err)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp, err := client.Do(req)
	s.Require().NoError(err)
	resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)

	// Verify avatar was uploaded
	updatedUser, err := s.datastore.Q.GetUserByID(s.T().Context(), user.ID)
	s.Require().NoError(err)
	s.Require().True(updatedUser.Picture.Valid)

	// Now delete the avatar (CSRF-aware: cookie from the jar, token in the form)
	resp, err = client.PostForm("http://localhost:8081/oauth/delete-avatar", url.Values{
		"csrf_token": {s.csrfTokenFromJar(client)},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()

	// Should redirect to change-avatar page
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	s.Require().Contains(resp.Header.Get("Location"), "/oauth/change-avatar")

	// Verify avatar was deleted
	updatedUser, err = s.datastore.Q.GetUserByID(s.T().Context(), user.ID)
	s.Require().NoError(err)
	s.Require().False(updatedUser.Picture.Valid)
}

func (s *AvatarFlowSuite) TestUserInfoReturnsPicture() {
	// This test verifies that the userinfo endpoint returns the picture claim
	// when the profile scope is present and user has an avatar

	// Create a test user and OAuth client
	user, password := s.mustRegisterUser()
	oauthClient := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(16),
		ClientSecret:   sql.NullString{String: s.mustGenerateRandomString(32), Valid: true},
		Name:           "Test Client",
		RedirectUris:   []string{"http://localhost:3000/callback"},
		AllowedScopes:  []string{"openid", "profile", "email"},
		IsConfidential: true,
		Audience:       "test-audience",
	})

	// First, upload an avatar for the user
	httpClient := s.loginAndGetClient(user, password)
	imgData, err := createTestJPEG(256, 256)
	s.Require().NoError(err)

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("avatar", "test.jpg")
	s.Require().NoError(err)
	_, err = io.Copy(part, bytes.NewReader(imgData))
	s.Require().NoError(err)
	s.Require().NoError(writer.WriteField("csrf_token", s.csrfTokenFromJar(httpClient)))
	s.Require().NoError(writer.Close())

	req, err := http.NewRequest("POST", "http://localhost:8081/oauth/change-avatar", body)
	s.Require().NoError(err)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp, err := httpClient.Do(req)
	s.Require().NoError(err)
	resp.Body.Close()

	// Verify avatar was uploaded
	updatedUser, err := s.datastore.Q.GetUserByID(s.T().Context(), user.ID)
	s.Require().NoError(err)
	s.Require().True(updatedUser.Picture.Valid)

	// Complete OAuth flow to get access token
	stateAndVerifier := s.mustGenerateStateAndCodeVerifier()
	code := s.mustCompleteAuthorizationFlow(httpClient, oauthClient, user, password, stateAndVerifier, []string{"openid", "profile", "email"})

	// Exchange code for token
	tokenResp := s.mustExchangeCodeForToken(oauthClient, code, stateAndVerifier)

	// Call userinfo endpoint
	req, err = http.NewRequest("GET", "http://localhost:8081/oauth/userinfo", nil)
	s.Require().NoError(err)
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)

	resp, err = s.httpClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Require().Equal(http.StatusOK, resp.StatusCode)

	// Parse response and verify picture is present
	bodyBytes, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	s.Require().Contains(string(bodyBytes), "picture")
	s.Require().Contains(string(bodyBytes), minioBucket)
}

// mustRegisterUser creates a new user for testing
func (s *AvatarFlowSuite) mustRegisterUser() (db.AuthUser, string) {
	password := "TestPassword123!"
	username := s.mustGenerateAlphanumericString(12)
	emailAddr := username + "@example.com"

	// Hash password
	passwordHash, err := auth.HashPassword(password)
	s.Require().NoError(err)

	user, err := s.datastore.Q.CreateUser(s.T().Context(), db.CreateUserParams{
		Username:     username,
		Email:        emailAddr,
		PasswordHash: passwordHash,
	})
	s.Require().NoError(err)

	return user, password
}

// mustGenerateRandomString generates a random string of the given length
func (s *AvatarFlowSuite) mustGenerateRandomString(length int) string {
	str, err := generateRandomString(length)
	s.Require().NoError(err)
	return str
}

// mustGenerateAlphanumericString generates a random alphanumeric string
func (s *AvatarFlowSuite) mustGenerateAlphanumericString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		randBytes := make([]byte, 1)
		_, err := rand.Read(randBytes)
		s.Require().NoError(err)
		b[i] = charset[int(randBytes[0])%len(charset)]
	}
	return string(b)
}

// mustRegisterOAuthClient creates an OAuth client for testing
func (s *AvatarFlowSuite) mustRegisterOAuthClient(params db.CreateOAuthClientParams) db.OauthClient {
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
	return client
}

// mustGenerateStateAndCodeVerifier generates PKCE values for OAuth flow
func (s *AvatarFlowSuite) mustGenerateStateAndCodeVerifier() StateAndCodeVerifier {
	state := s.mustGenerateRandomString(32)
	codeVerifier := s.mustGenerateRandomString(64)
	codeChallenge := generateCodeChallenge(codeVerifier)
	return StateAndCodeVerifier{
		State:               state,
		CodeVerifier:        codeVerifier,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: "S256",
	}
}

// codeFromLocation returns the authorization code embedded in a redirect
// Location header, or "" if the URL does not carry one.
func codeFromLocation(location string) string {
	if !strings.Contains(location, "code=") {
		return ""
	}
	parsed, err := url.Parse(location)
	if err != nil {
		return ""
	}
	return parsed.Query().Get("code")
}

// mustCompleteAuthorizationFlow drives the full authorization-code flow
// (login -> /oauth/authorize -> consent) and returns the authorization code.
// The server redirects through the consent screen on first authorization, so a
// successful login does not yield a code directly; this mirrors the OAuthFlowSuite
// helper mustLoginAndConsent.
func (s *AvatarFlowSuite) mustCompleteAuthorizationFlow(
	client *http.Client,
	oauthClient db.OauthClient,
	user db.AuthUser,
	password string,
	stateAndVerifier StateAndCodeVerifier,
	scopes []string,
) string {
	scope := strings.Join(scopes, " ")
	authParams := url.Values{
		"client_id":             {oauthClient.ClientID},
		"redirect_uri":          {oauthClient.RedirectUris[0]},
		"scope":                 {scope},
		"state":                 {stateAndVerifier.State},
		"code_challenge":        {stateAndVerifier.CodeChallenge},
		"code_challenge_method": {stateAndVerifier.CodeChallengeMethod},
	}

	// Step 1: hit /oauth/authorize. When unauthenticated this redirects to the
	// login page; when authenticated it redirects to the consent screen (or
	// straight back to the client with a code if consent was already granted).
	authURL := "http://localhost:8081/oauth/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {oauthClient.ClientID},
		"redirect_uri":          {oauthClient.RedirectUris[0]},
		"scope":                 {scope},
		"state":                 {stateAndVerifier.State},
		"code_challenge":        {stateAndVerifier.CodeChallenge},
		"code_challenge_method": {stateAndVerifier.CodeChallengeMethod},
	}.Encode()
	resp, err := client.Get(authURL)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusFound, resp.StatusCode, "authorize should redirect (to login, consent, or back to client)")
	location := resp.Header.Get("Location")
	resp.Body.Close()

	if code := codeFromLocation(location); code != "" {
		return code
	}

	// Step 2: if we were bounced to login, authenticate and follow the redirect
	// back to /oauth/authorize, which then redirects to the consent screen.
	if !strings.Contains(location, "/oauth/consent") {
		loginURL := "http://localhost:8081/oauth/login?" + authParams.Encode()
		form := url.Values{}
		form.Set("username", user.Username)
		form.Set("password", password)
		form.Set("csrf_token", s.csrfTokenFromJar(client))
		resp, err = client.PostForm(loginURL, form)
		s.Require().NoError(err)
		s.Require().Equal(http.StatusFound, resp.StatusCode)
		location = resp.Header.Get("Location")
		resp.Body.Close()

		if code := codeFromLocation(location); code != "" {
			return code
		}

		if !strings.HasPrefix(location, "http") {
			location = "http://localhost:8081" + location
		}
		resp, err = client.Get(location)
		s.Require().NoError(err)
		location = resp.Header.Get("Location")
		resp.Body.Close()

		if code := codeFromLocation(location); code != "" {
			return code
		}
	}

	// Step 3: approve consent, which redirects back to the client with the code.
	s.Require().Contains(location, "/oauth/consent")
	consentURL, err := url.Parse(location)
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
		"csrf_token":            {s.csrfTokenFromJar(client)},
	}
	resp, err = client.PostForm("http://localhost:8081/oauth/consent", consentForm)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	location = resp.Header.Get("Location")
	resp.Body.Close()

	code := codeFromLocation(location)
	s.Require().NotEmpty(code, "should receive authorization code")
	return code
}

// mustExchangeCodeForToken exchanges an authorization code for tokens
func (s *AvatarFlowSuite) mustExchangeCodeForToken(
	oauthClient db.OauthClient,
	code string,
	stateAndVerifier StateAndCodeVerifier,
) TokenResponse {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", oauthClient.RedirectUris[0])
	form.Set("client_id", oauthClient.ClientID)
	form.Set("client_secret", oauthClient.ClientSecret.String)
	form.Set("code_verifier", stateAndVerifier.CodeVerifier)

	resp, err := s.httpClient.PostForm("http://localhost:8081/oauth/token", form)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Require().Equal(http.StatusOK, resp.StatusCode)

	var tokenResp TokenResponse
	bodyBytes, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	err = json.Unmarshal(bodyBytes, &tokenResp)
	s.Require().NoError(err)

	return tokenResp
}

func TestAvatarFlowSuite(t *testing.T) {
	suite.Run(t, new(AvatarFlowSuite))
}
