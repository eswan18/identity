//go:build integration

package httpserver

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/eswan18/identity/pkg/db"
	"github.com/eswan18/identity/pkg/mfa"
)

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

	// Use cookie jar to maintain session across MFA → authorize → consent
	jar, err := cookiejar.New(nil)
	s.Require().NoError(err)
	httpClient := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Step 1: Submit login - should redirect to MFA page
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
	resp, err := csrfPostFormLogin(s.T(), httpClient, fmt.Sprintf("http://%s/oauth/login", host), formValues)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode, "login should redirect")

	location := resp.Header.Get("Location")
	s.Contains(location, "/oauth/mfa", "should redirect to MFA page")

	redirectUrl, err := url.ParseRequestURI(location)
	s.Require().NoError(err)
	pendingID := redirectUrl.Query().Get("pending")
	s.NotEmpty(pendingID, "should have pending ID")

	// Step 2: Submit valid MFA code - should redirect to /oauth/authorize
	validCode, err := generateTOTPCode(totpSecret)
	s.Require().NoError(err)

	resp, err = csrfPostFormLogin(s.T(), httpClient, fmt.Sprintf("http://%s/oauth/mfa", host), url.Values{
		"pending_id": {pendingID},
		"code":       {validCode},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode, "MFA verification should redirect")

	// Step 3: Follow redirect to /oauth/authorize → /oauth/consent
	authorizeURL := resp.Header.Get("Location")
	if !strings.HasPrefix(authorizeURL, "http") {
		authorizeURL = fmt.Sprintf("http://%s%s", host, authorizeURL)
	}
	resp, err = httpClient.Get(authorizeURL)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode, "authorize should redirect to consent")

	// Step 4: Approve consent
	consentLocation := resp.Header.Get("Location")
	consentURL, err := url.Parse(consentLocation)
	s.Require().NoError(err)
	resp, err = csrfPostFormLogin(s.T(), httpClient, fmt.Sprintf("http://%s/oauth/consent", host), url.Values{
		"decision":              {"allow"},
		"client_id":             {consentURL.Query().Get("client_id")},
		"redirect_uri":          {consentURL.Query().Get("redirect_uri")},
		"response_type":         {consentURL.Query().Get("response_type")},
		"scope":                 {consentURL.Query().Get("scope")},
		"state":                 {consentURL.Query().Get("state")},
		"code_challenge":        {consentURL.Query().Get("code_challenge")},
		"code_challenge_method": {consentURL.Query().Get("code_challenge_method")},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode, "consent should redirect to client")

	location = resp.Header.Get("Location")
	redirectUrl, err = url.ParseRequestURI(location)
	s.Require().NoError(err)
	s.Equal("/callback", redirectUrl.Path)
	authorizationCode := redirectUrl.Query().Get("code")
	s.NotEmpty(authorizationCode, "should receive authorization code")

	// Step 5: Exchange authorization code for tokens
	resp, err = httpClient.PostForm(fmt.Sprintf("http://%s/oauth/token", host), url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authorizationCode},
		"redirect_uri":  {clientCallbackURI},
		"client_id":     {client.ClientID},
		"code_verifier": {scv.CodeVerifier},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode, "token exchange should succeed")

	body, err := io.ReadAll(resp.Body)
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
	resp, err := csrfPostFormLogin(s.T(), s.httpClient, postLoginUrl, formValues)
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
	resp, err = csrfPostFormLogin(s.T(), s.httpClient, postMfaUrl, mfaFormValues)
	s.Require().NoError(err)
	defer resp.Body.Close()

	// Should return error page, not redirect
	s.Equal(http.StatusUnauthorized, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	s.Contains(string(body), "Invalid verification code")
}

// TestMFAPageRendersOAuthContext verifies the MFA verification page echoes the OAuth
// authorization parameters into hidden form fields. Without this, a pending row that
// expires or is consumed before the code is submitted strips the OAuth context, and the
// user is bounced to a context-free login (and then the account page).
func (s *OAuthFlowSuite) TestMFAPageRendersOAuthContext() {
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
	totpKey, err := mfa.GenerateSecret(user.Username)
	s.Require().NoError(err)
	s.mustEnableMFAForUser(user, mfa.GetSecret(totpKey))

	scv := s.mustCreateStateAndCodeVerifier()
	nonce := s.mustGenerateRandomString(16)
	host := "localhost:8080"

	// Login to reach the MFA page.
	resp, err := csrfPostFormLogin(s.T(), s.httpClient, fmt.Sprintf("http://%s/oauth/login", host), url.Values{
		"username":              {user.Username},
		"password":              {user.Password},
		"client_id":             {client.ClientID},
		"redirect_uri":          {clientCallbackURI},
		"state":                 {scv.State},
		"scope":                 {"openid profile email"},
		"code_challenge":        {scv.CodeChallenge},
		"code_challenge_method": {scv.CodeChallengeMethod},
		"nonce":                 {nonce},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	location := resp.Header.Get("Location")
	s.Require().Contains(location, "/oauth/mfa")

	mfaURL := location
	if !strings.HasPrefix(mfaURL, "http") {
		mfaURL = fmt.Sprintf("http://%s%s", host, mfaURL)
	}
	resp, err = s.httpClient.Get(mfaURL)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	html := string(body)

	s.Contains(html, fmt.Sprintf(`name="client_id" value="%s"`, client.ClientID))
	s.Contains(html, fmt.Sprintf(`name="redirect_uri" value="%s"`, clientCallbackURI))
	s.Contains(html, fmt.Sprintf(`name="state" value="%s"`, scv.State))
	s.Contains(html, fmt.Sprintf(`name="code_challenge" value="%s"`, scv.CodeChallenge))
	s.Contains(html, fmt.Sprintf(`name="nonce" value="%s"`, nonce))
}

// TestMFAPostWithExpiredPendingPreservesContext is the core regression test for the
// reported bug. When the pending MFA row is gone at code-submit time (here simulated by
// deleting it, as expiry would), the submit must resume the OAuth flow rather than
// strand the user on a context-free login that, on re-auth, lands on the account page.
func (s *OAuthFlowSuite) TestMFAPostWithExpiredPendingPreservesContext() {
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
	totpKey, err := mfa.GenerateSecret(user.Username)
	s.Require().NoError(err)
	totpSecret := mfa.GetSecret(totpKey)
	s.mustEnableMFAForUser(user, totpSecret)

	scv := s.mustCreateStateAndCodeVerifier()
	nonce := s.mustGenerateRandomString(16)
	host := "localhost:8080"

	resp, err := csrfPostFormLogin(s.T(), s.httpClient, fmt.Sprintf("http://%s/oauth/login", host), url.Values{
		"username":              {user.Username},
		"password":              {user.Password},
		"client_id":             {client.ClientID},
		"redirect_uri":          {clientCallbackURI},
		"state":                 {scv.State},
		"scope":                 {"openid profile email"},
		"code_challenge":        {scv.CodeChallenge},
		"code_challenge_method": {scv.CodeChallengeMethod},
		"nonce":                 {nonce},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	redirectURL, err := url.ParseRequestURI(resp.Header.Get("Location"))
	s.Require().NoError(err)
	pendingID := redirectURL.Query().Get("pending")
	s.Require().NotEmpty(pendingID)

	// Simulate the pending row vanishing before the code is submitted (expiry / replay).
	err = s.datastore.Q.DeleteMFAPending(s.T().Context(), pendingID)
	s.Require().NoError(err)

	validCode, err := generateTOTPCode(totpSecret)
	s.Require().NoError(err)

	// Submit the code together with the OAuth context the rendered page would carry.
	resp, err = csrfPostFormLogin(s.T(), s.httpClient, fmt.Sprintf("http://%s/oauth/mfa", host), url.Values{
		"pending_id":            {pendingID},
		"code":                  {validCode},
		"client_id":             {client.ClientID},
		"redirect_uri":          {clientCallbackURI},
		"state":                 {scv.State},
		"scope":                 {"openid profile email"},
		"code_challenge":        {scv.CodeChallenge},
		"code_challenge_method": {scv.CodeChallengeMethod},
		"nonce":                 {nonce},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)

	loc, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	// The OAuth context must be preserved: resume the authorize flow, NOT drop to the
	// account-settings page (the original bug).
	s.Equal("/oauth/authorize", loc.Path, "should resume the OAuth flow, not land on account settings")
	s.Equal(client.ClientID, loc.Query().Get("client_id"), "client_id must be preserved")
	s.Equal(clientCallbackURI, loc.Query().Get("redirect_uri"), "redirect_uri must be preserved")
	s.Equal(nonce, loc.Query().Get("nonce"), "nonce must be preserved")
}

// TestMFADoubleSubmitPreservesContext verifies that a duplicate/replayed MFA submit
// (the first already consumed the pending row and established the session) does not lose
// the OAuth context and strand the user on the account page.
func (s *OAuthFlowSuite) TestMFADoubleSubmitPreservesContext() {
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
	totpKey, err := mfa.GenerateSecret(user.Username)
	s.Require().NoError(err)
	totpSecret := mfa.GetSecret(totpKey)
	s.mustEnableMFAForUser(user, totpSecret)

	scv := s.mustCreateStateAndCodeVerifier()
	nonce := s.mustGenerateRandomString(16)
	host := "localhost:8080"

	jar, err := cookiejar.New(nil)
	s.Require().NoError(err)
	httpClient := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := csrfPostFormLogin(s.T(), httpClient, fmt.Sprintf("http://%s/oauth/login", host), url.Values{
		"username":              {user.Username},
		"password":              {user.Password},
		"client_id":             {client.ClientID},
		"redirect_uri":          {clientCallbackURI},
		"state":                 {scv.State},
		"scope":                 {"openid profile email"},
		"code_challenge":        {scv.CodeChallenge},
		"code_challenge_method": {scv.CodeChallengeMethod},
		"nonce":                 {nonce},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	redirectURL, err := url.ParseRequestURI(resp.Header.Get("Location"))
	s.Require().NoError(err)
	pendingID := redirectURL.Query().Get("pending")
	s.Require().NotEmpty(pendingID)

	validCode, err := generateTOTPCode(totpSecret)
	s.Require().NoError(err)

	mfaForm := url.Values{
		"pending_id":            {pendingID},
		"code":                  {validCode},
		"client_id":             {client.ClientID},
		"redirect_uri":          {clientCallbackURI},
		"state":                 {scv.State},
		"scope":                 {"openid profile email"},
		"code_challenge":        {scv.CodeChallenge},
		"code_challenge_method": {scv.CodeChallengeMethod},
		"nonce":                 {nonce},
	}

	// First submit: succeeds, consumes the pending row, and sets the session cookie.
	resp, err = csrfPostFormLogin(s.T(), httpClient, fmt.Sprintf("http://%s/oauth/mfa", host), mfaForm)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	loc1, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Equal("/oauth/authorize", loc1.Path)
	s.Equal(client.ClientID, loc1.Query().Get("client_id"))
	var hasSession bool
	for _, c := range resp.Cookies() {
		if c.Name == "session_id" && c.Value != "" {
			hasSession = true
		}
	}
	s.True(hasSession, "first MFA submit should establish a session")

	// Second submit (replay): the pending row is already gone. The flow must still be
	// preserved — resume authorize, not bounce to account settings.
	resp, err = csrfPostFormLogin(s.T(), httpClient, fmt.Sprintf("http://%s/oauth/mfa", host), mfaForm)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	loc2, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Equal("/oauth/authorize", loc2.Path, "replayed submit must not drop to account settings")
	s.Equal(client.ClientID, loc2.Query().Get("client_id"), "client_id must be preserved on replay")
}

// TestMFALoginSetsLastLoginAt verifies that successful MFA login updates the last_login_at timestamp.
func (s *OAuthFlowSuite) TestMFALoginSetsLastLoginAt() {
	// Register a user with MFA enabled
	username := s.mustGenerateRandomString(8)
	password := s.mustGenerateRandomString(16)
	email := fmt.Sprintf("%s@example.com", s.mustGenerateRandomString(8))
	user := s.mustRegisterUser(username, password, email)

	// Enable MFA
	totpKey, err := mfa.GenerateSecret(user.Username)
	s.Require().NoError(err)
	totpSecret := mfa.GetSecret(totpKey)
	s.mustEnableMFAForUser(user, totpSecret)

	// Verify last_login_at is initially NULL
	userBefore, err := s.datastore.Q.GetUserByID(s.T().Context(), user.ID)
	s.Require().NoError(err)
	s.False(userBefore.LastLoginAt.Valid, "last_login_at should be NULL before first login")

	// Create an OAuth client
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

	// Step 1: Login (should redirect to MFA)
	resp, err := csrfPostFormLogin(s.T(), s.httpClient, "http://localhost:8080/oauth/login", url.Values{
		"username":              {username},
		"password":              {password},
		"client_id":             {client.ClientID},
		"redirect_uri":          {client.RedirectUris[0]},
		"state":                 {scv.State},
		"scope":                 {"openid"},
		"code_challenge":        {scv.CodeChallenge},
		"code_challenge_method": {scv.CodeChallengeMethod},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)

	// Extract pending ID from redirect
	location := resp.Header.Get("Location")
	s.Require().Contains(location, "/oauth/mfa")
	redirectUrl, err := url.ParseRequestURI(location)
	s.Require().NoError(err)
	pendingID := redirectUrl.Query().Get("pending")
	s.Require().NotEmpty(pendingID)

	// Verify last_login_at is still NULL (MFA not completed yet)
	userMid, err := s.datastore.Q.GetUserByID(s.T().Context(), user.ID)
	s.Require().NoError(err)
	s.False(userMid.LastLoginAt.Valid, "last_login_at should still be NULL before MFA completion")

	// Step 2: Complete MFA
	totpCode, err := generateTOTPCode(totpSecret)
	s.Require().NoError(err)

	resp, err = csrfPostFormLogin(s.T(), s.httpClient, "http://localhost:8080/oauth/mfa", url.Values{
		"pending_id": {pendingID},
		"code":       {totpCode},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode, "MFA should succeed with redirect")

	// Verify last_login_at is now set
	userAfter, err := s.datastore.Q.GetUserByID(s.T().Context(), user.ID)
	s.Require().NoError(err)
	s.True(userAfter.LastLoginAt.Valid, "last_login_at should be set after MFA login")
	s.WithinDuration(time.Now(), userAfter.LastLoginAt.Time, 5*time.Second, "last_login_at should be recent")
}
