//go:build integration

package httpserver

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/eswan18/identity/pkg/db"
)

func (s *OAuthFlowSuite) TestAdminCreateUser_WithClientCredentials() {
	// Create a confidential client with admin scope
	clientSecret := s.mustGenerateRandomString(32)
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: clientSecret, Valid: true},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"admin:users:write"},
		IsConfidential: true,
		Audience:       "http://localhost:8080",
	})

	// Get access token via client credentials
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

	// Create user via admin API
	newUsername := s.mustGenerateAlphanumericString(8)
	newEmail := fmt.Sprintf("%s@example.com", s.mustGenerateAlphanumericString(8))
	newPassword := "SecureP@ssword123!"

	createUserReq := CreateUserRequest{
		Username: newUsername,
		Email:    newEmail,
		Password: newPassword,
	}
	reqBody, err := json.Marshal(createUserReq)
	s.Require().NoError(err)

	req, err := http.NewRequest("POST", "http://localhost:8080/admin/users", strings.NewReader(string(reqBody)))
	s.Require().NoError(err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tokenResponse.AccessToken)

	resp, err = s.httpClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusCreated, resp.StatusCode)

	body, err = io.ReadAll(resp.Body)
	s.Require().NoError(err)
	var createUserResp CreateUserResponse
	err = json.Unmarshal(body, &createUserResp)
	s.Require().NoError(err)

	// Verify response
	s.NotEmpty(createUserResp.ID)
	s.Equal(newUsername, createUserResp.Username)
	s.Equal(strings.ToLower(newEmail), createUserResp.Email) // Email should be lowercased
	s.True(createUserResp.IsActive)
	s.False(createUserResp.EmailVerified)

	// Verify user can login with the created credentials
	scv := s.mustCreateStateAndCodeVerifier()
	loginValues := url.Values{
		"username":              {newUsername},
		"password":              {newPassword},
		"client_id":             {client.ClientID},
		"redirect_uri":          {client.RedirectUris[0]},
		"state":                 {scv.State},
		"scope":                 {"admin:users:write"},
		"code_challenge":        {scv.CodeChallenge},
		"code_challenge_method": {scv.CodeChallengeMethod},
	}
	resp, err = s.httpClient.PostForm("http://localhost:8080/oauth/login", loginValues)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusFound, resp.StatusCode, "user should be able to login with created credentials")
}

// TestAdminCreateUser_MissingAuth verifies unauthenticated requests are rejected
func (s *OAuthFlowSuite) TestAdminCreateUser_MissingAuth() {
	createUserReq := CreateUserRequest{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "SecureP@ssword123!",
	}
	reqBody, err := json.Marshal(createUserReq)
	s.Require().NoError(err)

	req, err := http.NewRequest("POST", "http://localhost:8080/admin/users", strings.NewReader(string(reqBody)))
	s.Require().NoError(err)
	req.Header.Set("Content-Type", "application/json")
	// No Authorization header

	resp, err := s.httpClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusUnauthorized, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	var errorResponse map[string]string
	err = json.Unmarshal(body, &errorResponse)
	s.Require().NoError(err)
	s.Equal("invalid_token", errorResponse["error"])
}

// TestAdminCreateUser_InsufficientScope verifies scope checking
func (s *OAuthFlowSuite) TestAdminCreateUser_InsufficientScope() {
	// Create a confidential client with only read scope (not write)
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

	// Get access token with read scope
	tokenValues := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {client.ClientID},
		"client_secret": {clientSecret},
		"scope":         {"admin:users:read"},
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

	// Try to create user (requires write scope)
	createUserReq := CreateUserRequest{
		Username: s.mustGenerateAlphanumericString(8),
		Email:    fmt.Sprintf("%s@example.com", s.mustGenerateAlphanumericString(8)),
		Password: "SecureP@ssword123!",
	}
	reqBody, err := json.Marshal(createUserReq)
	s.Require().NoError(err)

	req, err := http.NewRequest("POST", "http://localhost:8080/admin/users", strings.NewReader(string(reqBody)))
	s.Require().NoError(err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tokenResponse.AccessToken)

	resp, err = s.httpClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusForbidden, resp.StatusCode)

	body, err = io.ReadAll(resp.Body)
	s.Require().NoError(err)
	var errorResponse map[string]string
	err = json.Unmarshal(body, &errorResponse)
	s.Require().NoError(err)
	s.Equal("insufficient_scope", errorResponse["error"])
}

// TestAdminCreateUser_DuplicateUsername verifies conflict handling
func (s *OAuthFlowSuite) TestAdminCreateUser_DuplicateUsername() {
	// Create a confidential client with admin scope
	clientSecret := s.mustGenerateRandomString(32)
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: clientSecret, Valid: true},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"admin:users:write"},
		IsConfidential: true,
		Audience:       "http://localhost:8080",
	})

	// Get access token
	tokenValues := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {client.ClientID},
		"client_secret": {clientSecret},
		"scope":         {"admin:users:write"},
	}
	resp, err := s.httpClient.PostForm("http://localhost:8080/oauth/token", tokenValues)
	s.Require().NoError(err)
	defer resp.Body.Close()
	var tokenResponse TokenResponse
	json.NewDecoder(resp.Body).Decode(&tokenResponse)

	// Create first user
	username := s.mustGenerateAlphanumericString(8)
	createUserReq := CreateUserRequest{
		Username: username,
		Email:    fmt.Sprintf("%s@example.com", s.mustGenerateAlphanumericString(8)),
		Password: "SecureP@ssword123!",
	}
	reqBody, _ := json.Marshal(createUserReq)

	req, _ := http.NewRequest("POST", "http://localhost:8080/admin/users", strings.NewReader(string(reqBody)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tokenResponse.AccessToken)
	resp, _ = s.httpClient.Do(req)
	resp.Body.Close()
	s.Require().Equal(http.StatusCreated, resp.StatusCode)

	// Try to create second user with same username
	createUserReq.Email = fmt.Sprintf("%s@example.com", s.mustGenerateAlphanumericString(8)) // Different email
	reqBody, _ = json.Marshal(createUserReq)
	req, _ = http.NewRequest("POST", "http://localhost:8080/admin/users", strings.NewReader(string(reqBody)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tokenResponse.AccessToken)

	resp, err = s.httpClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusConflict, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	var errorResponse map[string]string
	json.Unmarshal(body, &errorResponse)
	s.Equal("conflict", errorResponse["error"])
	s.Contains(errorResponse["error_description"], "Username already exists")
}

// TestAdminCreateUser_InvalidPassword verifies password validation
func (s *OAuthFlowSuite) TestAdminCreateUser_InvalidPassword() {
	// Create a confidential client with admin scope
	clientSecret := s.mustGenerateRandomString(32)
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: clientSecret, Valid: true},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"admin:users:write"},
		IsConfidential: true,
		Audience:       "http://localhost:8080",
	})

	// Get access token
	tokenValues := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {client.ClientID},
		"client_secret": {clientSecret},
		"scope":         {"admin:users:write"},
	}
	resp, err := s.httpClient.PostForm("http://localhost:8080/oauth/token", tokenValues)
	s.Require().NoError(err)
	defer resp.Body.Close()
	var tokenResponse TokenResponse
	json.NewDecoder(resp.Body).Decode(&tokenResponse)

	// Try to create user with weak password
	createUserReq := CreateUserRequest{
		Username: s.mustGenerateAlphanumericString(8),
		Email:    fmt.Sprintf("%s@example.com", s.mustGenerateAlphanumericString(8)),
		Password: "weak", // Too short
	}
	reqBody, _ := json.Marshal(createUserReq)

	req, _ := http.NewRequest("POST", "http://localhost:8080/admin/users", strings.NewReader(string(reqBody)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tokenResponse.AccessToken)

	resp, err = s.httpClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusBadRequest, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	var errorResponse map[string]string
	json.Unmarshal(body, &errorResponse)
	s.Equal("invalid_request", errorResponse["error"])
}

// TestAdminListUsers tests the list users endpoint
func (s *OAuthFlowSuite) TestAdminListUsers() {
	// Create a confidential client with read scope
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

	// Create a few users via admin API first
	writeToken := s.mustGetClientCredentialsToken(client.ClientID, clientSecret, "admin:users:write")
	for i := 0; i < 3; i++ {
		s.mustCreateUserViaAdminAPI(writeToken, s.mustGenerateAlphanumericString(8),
			fmt.Sprintf("%s@example.com", s.mustGenerateAlphanumericString(8)), "SecureP@ssword123!")
	}

	// Get read token and list users
	readToken := s.mustGetClientCredentialsToken(client.ClientID, clientSecret, "admin:users:read")

	req, err := http.NewRequest("GET", "http://localhost:8080/admin/users?limit=10&offset=0", nil)
	s.Require().NoError(err)
	req.Header.Set("Authorization", "Bearer "+readToken)

	resp, err := s.httpClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	var listResponse ListUsersResponse
	err = json.Unmarshal(body, &listResponse)
	s.Require().NoError(err)

	// Verify response structure
	s.GreaterOrEqual(len(listResponse.Users), 3, "should have at least 3 users")
	s.GreaterOrEqual(listResponse.Total, int64(3), "total should be at least 3")
	s.Equal(10, listResponse.Limit)
	s.Equal(0, listResponse.Offset)

	// Verify user fields are populated
	for _, user := range listResponse.Users {
		s.NotEmpty(user.ID)
		s.NotEmpty(user.Username)
		s.NotEmpty(user.Email)
		s.NotEmpty(user.CreatedAt)
		s.NotEmpty(user.UpdatedAt)
	}
}

// TestAdminListUsers_Pagination tests pagination in list users
func (s *OAuthFlowSuite) TestAdminListUsers_Pagination() {
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

	// Create 5 users
	writeToken := s.mustGetClientCredentialsToken(client.ClientID, clientSecret, "admin:users:write")
	for i := 0; i < 5; i++ {
		s.mustCreateUserViaAdminAPI(writeToken, s.mustGenerateAlphanumericString(8),
			fmt.Sprintf("%s@example.com", s.mustGenerateAlphanumericString(8)), "SecureP@ssword123!")
	}

	readToken := s.mustGetClientCredentialsToken(client.ClientID, clientSecret, "admin:users:read")

	// Get first page with limit 2
	req, err := http.NewRequest("GET", "http://localhost:8080/admin/users?limit=2&offset=0", nil)
	s.Require().NoError(err)
	req.Header.Set("Authorization", "Bearer "+readToken)
	resp, err := s.httpClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	var page1 ListUsersResponse
	json.Unmarshal(body, &page1)

	s.Equal(2, len(page1.Users))
	s.True(page1.HasMore, "should have more users")

	// Get second page
	req, err = http.NewRequest("GET", "http://localhost:8080/admin/users?limit=2&offset=2", nil)
	s.Require().NoError(err)
	req.Header.Set("Authorization", "Bearer "+readToken)
	resp, err = s.httpClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()

	body, _ = io.ReadAll(resp.Body)
	var page2 ListUsersResponse
	json.Unmarshal(body, &page2)

	s.Equal(2, len(page2.Users))
	s.Equal(2, page2.Offset)

	// Ensure different users on each page
	s.NotEqual(page1.Users[0].ID, page2.Users[0].ID)
}

// TestAdminListUsers_MissingAuth tests unauthenticated request
func (s *OAuthFlowSuite) TestAdminListUsers_MissingAuth() {
	req, _ := http.NewRequest("GET", "http://localhost:8080/admin/users", nil)
	resp, err := s.httpClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusUnauthorized, resp.StatusCode)
}

// TestAdminListUsers_InsufficientScope tests scope validation
func (s *OAuthFlowSuite) TestAdminListUsers_InsufficientScope() {
	clientSecret := s.mustGenerateRandomString(32)
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: clientSecret, Valid: true},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"admin:users:write"}, // Only write, not read
		IsConfidential: true,
		Audience:       "http://localhost:8080",
	})

	writeToken := s.mustGetClientCredentialsToken(client.ClientID, clientSecret, "admin:users:write")

	req, _ := http.NewRequest("GET", "http://localhost:8080/admin/users", nil)
	req.Header.Set("Authorization", "Bearer "+writeToken)
	resp, err := s.httpClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusForbidden, resp.StatusCode)
}

// TestAdminGetUser tests getting a single user by ID
func (s *OAuthFlowSuite) TestAdminGetUser() {
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

	// Create a user first
	writeToken := s.mustGetClientCredentialsToken(client.ClientID, clientSecret, "admin:users:write")
	username := s.mustGenerateAlphanumericString(8)
	email := fmt.Sprintf("%s@example.com", s.mustGenerateAlphanumericString(8))
	createdUser := s.mustCreateUserViaAdminAPI(writeToken, username, email, "SecureP@ssword123!")

	// Get the user by ID
	readToken := s.mustGetClientCredentialsToken(client.ClientID, clientSecret, "admin:users:read")

	req, err := http.NewRequest("GET", "http://localhost:8080/admin/users/"+createdUser.ID, nil)
	s.Require().NoError(err)
	req.Header.Set("Authorization", "Bearer "+readToken)

	resp, err := s.httpClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	var userResponse UserResponse
	err = json.Unmarshal(body, &userResponse)
	s.Require().NoError(err)

	// Verify user data matches
	s.Equal(createdUser.ID, userResponse.ID)
	s.Equal(username, userResponse.Username)
	s.Equal(strings.ToLower(email), userResponse.Email)
	s.True(userResponse.IsActive)
	s.False(userResponse.EmailVerified)
	s.False(userResponse.MFAEnabled)
}

// TestAdminGetUser_NotFound tests 404 response for non-existent user
func (s *OAuthFlowSuite) TestAdminGetUser_NotFound() {
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

	readToken := s.mustGetClientCredentialsToken(client.ClientID, clientSecret, "admin:users:read")

	// Use a random UUID that doesn't exist
	req, _ := http.NewRequest("GET", "http://localhost:8080/admin/users/00000000-0000-0000-0000-000000000000", nil)
	req.Header.Set("Authorization", "Bearer "+readToken)

	resp, err := s.httpClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusNotFound, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	var errorResponse map[string]string
	json.Unmarshal(body, &errorResponse)
	s.Equal("not_found", errorResponse["error"])
}

// TestAdminGetUser_InvalidID tests 400 response for invalid UUID
func (s *OAuthFlowSuite) TestAdminGetUser_InvalidID() {
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

	readToken := s.mustGetClientCredentialsToken(client.ClientID, clientSecret, "admin:users:read")

	req, _ := http.NewRequest("GET", "http://localhost:8080/admin/users/not-a-uuid", nil)
	req.Header.Set("Authorization", "Bearer "+readToken)

	resp, err := s.httpClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusBadRequest, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	var errorResponse map[string]string
	json.Unmarshal(body, &errorResponse)
	s.Equal("invalid_request", errorResponse["error"])
}

// Helper function to get a client credentials token
