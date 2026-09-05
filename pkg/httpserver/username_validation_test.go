//go:build integration

package httpserver

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"

	"github.com/eswan18/identity/pkg/db"
)

// payloadUsername returns the injection payload the username rule exists to
// refuse: it closes the surrounding <p> in the verification email, adds an
// anchor of its own, and reopens a <p> so the rest of the message still renders.
//
// The payload is made unique per caller deliberately. A single shared constant
// makes these tests pass vacuously: with validation removed, the first test to
// run creates an account holding the payload, and every later test then trips
// "Username is already taken" -- which is also a 400, so the assertion still
// succeeds and the mutation goes undetected. Uniqueness keeps each test's 400
// attributable to validation and nothing else.
func (s *OAuthFlowSuite) payloadUsername() string {
	s.T().Helper()
	return fmt.Sprintf(`</p><a href="https://evil.example/%s">Reset your password</a><p>`,
		s.mustGenerateAlphanumericString(8))
}

// These tests cover the *wiring* of auth.ValidateUsername, not the rule itself
// (pkg/auth/validate_test.go covers the rule). Without them, deleting the
// validation call from any of the three handlers that set a username leaves the
// entire suite green -- which was true when this validation was first added.
// Each test therefore asserts both the rejection and that no username was
// persisted, so a handler that returns 400 after writing would still fail.

// TestRegisterRejectsInvalidUsername covers the self-service registration path,
// the one an unauthenticated attacker reaches.
func (s *OAuthFlowSuite) TestRegisterRejectsInvalidUsername() {
	badUsername := s.payloadUsername()
	emailAddr := fmt.Sprintf("%s@example.com", s.mustGenerateAlphanumericString(10))
	password := "securepassword123"

	resp, err := csrfPostFormLogin(s.T(), s.httpClient, "http://localhost:8080/oauth/register", url.Values{
		"username":         {badUsername},
		"email":            {emailAddr},
		"password":         {password},
		"confirm_password": {password},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Require().Equal(http.StatusBadRequest, resp.StatusCode,
		"registration must reject a username containing markup")

	// And the account must not exist: a 400 returned after the INSERT would be
	// just as broken as no check at all.
	_, err = s.datastore.Q.GetUserByUsernameIncludingInactive(s.T().Context(), badUsername)
	s.Require().ErrorIs(err, sql.ErrNoRows, "no user should have been created")
}

// TestChangeUsernameRejectsInvalidUsername covers the authenticated path. This is
// the one that mattered most in practice: it let an attacker set the payload on an
// account that had already been created with a innocuous name.
func (s *OAuthFlowSuite) TestChangeUsernameRejectsInvalidUsername() {
	badUsername := s.payloadUsername()
	username := s.mustGenerateAlphanumericString(10)
	password := s.mustGenerateAlphanumericString(16)
	user := s.mustRegisterUser(username, password, fmt.Sprintf("%s@example.com", username))

	httpClient := s.mustLoginAsUser(username, password)

	resp, err := csrfPostFormLogin(s.T(), httpClient, "http://localhost:8080/oauth/change-username", url.Values{
		"new_username": {badUsername},
		"password":     {password},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Require().Equal(http.StatusBadRequest, resp.StatusCode,
		"change-username must reject a username containing markup")

	// The stored username must be untouched.
	after, err := s.datastore.Q.GetUserByIDIncludingInactive(s.T().Context(), user.ID)
	s.Require().NoError(err)
	s.Require().Equal(username, after.Username, "username must not have been changed")
}

// TestAdminCreateUserRejectsInvalidUsername covers the admin API. It already had
// this rule before the shared validator existed; this pins that collapsing the
// three call sites onto auth.ValidateUsername did not loosen it.
func (s *OAuthFlowSuite) TestAdminCreateUserRejectsInvalidUsername() {
	badUsername := s.payloadUsername()
	clientSecret := s.mustGenerateRandomString(32)
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID: s.mustGenerateRandomString(8),
		// mustRegisterOAuthClient hashes this before insert and hands the
		// plaintext back, so pass the raw secret here.
		ClientSecret:   sql.NullString{String: clientSecret, Valid: true},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"admin:users:write"},
		IsConfidential: true,
		Audience:       "http://localhost:8080",
	})
	token := s.mustGetClientCredentialsToken(client.ClientID, clientSecret, "admin:users:write")

	body, err := json.Marshal(CreateUserRequest{
		Username: badUsername,
		Email:    fmt.Sprintf("%s@example.com", s.mustGenerateAlphanumericString(10)),
		Password: "securepassword123",
	})
	s.Require().NoError(err)

	req, err := http.NewRequest(http.MethodPost, "http://localhost:8080/admin/users", strings.NewReader(string(body)))
	s.Require().NoError(err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := s.httpClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Require().Equal(http.StatusBadRequest, resp.StatusCode,
		"admin user creation must reject a username containing markup")

	_, err = s.datastore.Q.GetUserByUsernameIncludingInactive(s.T().Context(), badUsername)
	s.Require().ErrorIs(err, sql.ErrNoRows, "no user should have been created")
}

// mustLoginAsUser logs in with username/password and returns a client whose jar
// carries the resulting session. Unlike mustLoginAndGetAuthorizeClient it does
// not create the user or an OAuth client, so the caller keeps the handle it
// needs to assert on the stored row.
func (s *OAuthFlowSuite) mustLoginAsUser(username, password string) *http.Client {
	s.T().Helper()
	jar, err := cookiejar.New(nil)
	s.Require().NoError(err)
	httpClient := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := csrfPostFormLogin(s.T(), httpClient, "http://localhost:8080/oauth/login", url.Values{
		"username": {username},
		"password": {password},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode, "login should redirect on success")

	return httpClient
}
