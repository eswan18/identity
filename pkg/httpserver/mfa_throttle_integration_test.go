//go:build integration

package httpserver

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/eswan18/identity/pkg/db"
	"github.com/eswan18/identity/pkg/mfa"
)

// TestMFAAttemptsAreThrottledPerAccount drives the real brute-force against a
// real server: the same account, guessing wrong codes, until the budget is gone.
//
// The assertion that matters is the last one. Exhausting the budget must not
// merely change the error text -- it has to stop verification happening at all,
// so a correct code submitted afterwards still yields no session. Otherwise the
// throttle is decoration.
//
// The CSRF token is fetched once and reused rather than re-fetched per request:
// the double-submit check only compares the cookie against the form value, and
// this keeps a seven-request test clear of the global per-IP limiter.
func (s *OAuthFlowSuite) TestMFAAttemptsAreThrottledPerAccount() {
	user, totpSecret, client := s.mustCreateMFAUser()

	csrfToken, csrfCookie := fetchCSRFToken(s.T(), s.httpClient, "http://localhost:8080/oauth/login")
	pendingID := s.mustReachMFAStep(user, client, csrfToken, csrfCookie)

	// Spend the budget on wrong codes. Each leaves the pending row intact so the
	// user can retry, which is what made unlimited guessing possible.
	for i := 1; i <= mfaAttemptBurst; i++ {
		resp := s.postWithCSRF("http://localhost:8080/oauth/mfa", csrfToken, csrfCookie, url.Values{
			"pending_id": {pendingID},
			"code":       {"000000"},
		})
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		s.Require().Equal(http.StatusUnauthorized, resp.StatusCode,
			"attempt %d should be a plain wrong-code rejection", i)
		s.Require().Contains(string(body), "Invalid verification code")
	}

	// One more is refused before the code is even checked.
	resp := s.postWithCSRF("http://localhost:8080/oauth/mfa", csrfToken, csrfCookie, url.Values{
		"pending_id": {pendingID},
		"code":       {"000000"},
	})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	s.Require().Equal(http.StatusTooManyRequests, resp.StatusCode,
		"the account's attempt budget should be spent")
	s.Require().Contains(string(body), "Too many incorrect codes")

	// The pending row is consumed, so resuming requires a fresh password login.
	_, err := s.datastore.Q.GetMFAPending(s.T().Context(), pendingID)
	s.Require().Error(err, "exhausting the budget must invalidate the pending login")

	// And the decisive one: a CORRECT code now gets the attacker nowhere.
	validCode, err := generateTOTPCode(totpSecret)
	s.Require().NoError(err)
	resp = s.postWithCSRF("http://localhost:8080/oauth/mfa", csrfToken, csrfCookie, url.Values{
		"pending_id": {pendingID},
		"code":       {validCode},
	})
	defer resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name == "session_id" && c.Value != "" {
			s.Failf("session issued after the budget was exhausted",
				"a correct code must not complete a login whose pending row was invalidated")
		}
	}
}

// TestMFAThrottleDoesNotAffectOtherAccounts: one account exhausting its budget
// must not deny another user their second factor. A global budget would turn
// this control into a denial of service against every user at once.
func (s *OAuthFlowSuite) TestMFAThrottleDoesNotAffectOtherAccounts() {
	victim, _, client := s.mustCreateMFAUser()
	csrfToken, csrfCookie := fetchCSRFToken(s.T(), s.httpClient, "http://localhost:8080/oauth/login")
	pendingID := s.mustReachMFAStep(victim, client, csrfToken, csrfCookie)

	for i := 0; i <= mfaAttemptBurst; i++ {
		resp := s.postWithCSRF("http://localhost:8080/oauth/mfa", csrfToken, csrfCookie, url.Values{
			"pending_id": {pendingID},
			"code":       {"000000"},
		})
		resp.Body.Close()
	}

	// A second account, with its own budget, still gets a normal wrong-code
	// rejection rather than the throttled one.
	other, _, otherClient := s.mustCreateMFAUser()
	otherPending := s.mustReachMFAStep(other, otherClient, csrfToken, csrfCookie)

	resp := s.postWithCSRF("http://localhost:8080/oauth/mfa", csrfToken, csrfCookie, url.Values{
		"pending_id": {otherPending},
		"code":       {"000000"},
	})
	defer resp.Body.Close()
	s.Require().Equal(http.StatusUnauthorized, resp.StatusCode,
		"a second account must have its own attempt budget")
}

// mustCreateMFAUser registers a user with MFA enabled plus a client to log in
// through, returning the user, its TOTP secret, and the client.
func (s *OAuthFlowSuite) mustCreateMFAUser() (UserWithPassword, string, db.OauthClient) {
	s.T().Helper()
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid", "profile", "email"},
		IsConfidential: false,
		Audience:       "http://localhost:8080",
	})
	user := s.mustRegisterUser(
		s.mustGenerateAlphanumericString(10),
		s.mustGenerateAlphanumericString(16),
		fmt.Sprintf("%s@example.com", s.mustGenerateAlphanumericString(10)),
	)
	key, err := mfa.GenerateSecret(user.Username)
	s.Require().NoError(err)
	secret := mfa.GetSecret(key)
	s.mustEnableMFAForUser(user, secret)
	return user, secret, client
}

// mustReachMFAStep logs in with a valid password and returns the pending MFA id.
// Reaching this step at all requires the password, which is why spending an
// account's attempt budget is not something a stranger can do.
func (s *OAuthFlowSuite) mustReachMFAStep(user UserWithPassword, client db.OauthClient, csrfToken string, csrfCookie *http.Cookie) string {
	s.T().Helper()
	scv := s.mustCreateStateAndCodeVerifier()

	resp := s.postWithCSRF("http://localhost:8080/oauth/login", csrfToken, csrfCookie, url.Values{
		"username":              {user.Username},
		"password":              {user.Password},
		"client_id":             {client.ClientID},
		"redirect_uri":          {client.RedirectUris[0]},
		"state":                 {scv.State},
		"scope":                 {"openid profile email"},
		"code_challenge":        {scv.CodeChallenge},
		"code_challenge_method": {scv.CodeChallengeMethod},
	})
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)

	location, err := url.ParseRequestURI(resp.Header.Get("Location"))
	s.Require().NoError(err)
	pendingID := location.Query().Get("pending")
	s.Require().NotEmpty(pendingID, "login with MFA enabled should redirect to the MFA step")
	return pendingID
}

// postWithCSRF posts a form using a CSRF token and cookie obtained once, instead
// of re-fetching a form page per request as csrfPostForm does.
func (s *OAuthFlowSuite) postWithCSRF(postURL, token string, cookie *http.Cookie, form url.Values) *http.Response {
	s.T().Helper()
	form.Set("csrf_token", token)
	req, err := http.NewRequest(http.MethodPost, postURL, strings.NewReader(form.Encode()))
	s.Require().NoError(err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp, err := s.httpClient.Do(req)
	s.Require().NoError(err)
	return resp
}
