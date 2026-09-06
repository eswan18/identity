//go:build integration

package httpserver

import (
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
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

	// One more is refused before the code is even checked, and redirected to
	// login rather than re-rendering the MFA form: the pending row is destroyed
	// at this point, so every field on that form would be dead.
	resp := s.postWithCSRF("http://localhost:8080/oauth/mfa", csrfToken, csrfCookie, url.Values{
		"pending_id": {pendingID},
		"code":       {"000000"},
	})
	resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode,
		"the account's attempt budget should be spent")
	s.Require().Contains(resp.Header.Get("Location"), "mfa_throttled")
	s.Require().Contains(resp.Header.Get("Location"), "client_id",
		"the OAuth context must survive so a fresh sign-in returns to the app")

	// The pending row is consumed, so resuming requires a fresh password login.
	_, err := s.datastore.Q.GetMFAPending(s.T().Context(), pendingID)
	s.Require().Error(err, "exhausting the budget must invalidate the pending login")

	// The decisive assertion: a CORRECT code, against a LIVE pending row, still
	// gets nowhere while the account is over budget.
	//
	// Submitting against the row deleted above would prove nothing -- the handler
	// returns early when the row is missing and never reaches the throttle or the
	// code check, so that assertion passes whether or not the throttle gates
	// verification at all. It did exactly that in an earlier version of this
	// test, which stayed green against a build where a correct code logged in
	// while over budget. Logging in again is what makes the check meaningful.
	freshPending := s.mustReachMFAStep(user, client, csrfToken, csrfCookie)
	validCode, err := generateTOTPCode(totpSecret)
	s.Require().NoError(err)

	resp = s.postWithCSRF("http://localhost:8080/oauth/mfa", csrfToken, csrfCookie, url.Values{
		"pending_id": {freshPending},
		"code":       {validCode},
	})
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	s.Require().Contains(resp.Header.Get("Location"), "mfa_throttled",
		"a correct code must be refused while the account is over budget")
	for _, c := range resp.Cookies() {
		if c.Name == "session_id" && c.Value != "" {
			s.Fail("session issued while over budget",
				"the throttle must stop verification, not merely change the error text")
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

	var victimThrottled bool
	for i := 0; i <= mfaAttemptBurst; i++ {
		resp := s.postWithCSRF("http://localhost:8080/oauth/mfa", csrfToken, csrfCookie, url.Values{
			"pending_id": {pendingID},
			"code":       {"000000"},
		})
		if resp.StatusCode == http.StatusFound &&
			strings.Contains(resp.Header.Get("Location"), "mfa_throttled") {
			victimThrottled = true
		}
		resp.Body.Close()
	}
	// Without this the test passes when no throttle exists at all: the second
	// account's 401 is simply the normal wrong-code response.
	s.Require().True(victimThrottled, "the first account should have exhausted its budget")

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

// TestMFADisableIsThrottled covers the endpoint that is a better target than the
// login one: succeeding here does not get past the second factor, it removes it.
// It sits behind a session and a password, but so does nothing else that bounds
// it -- the per-IP limiter is not a bound on a per-account guess, which is the
// whole argument for throttling the login path.
func (s *OAuthFlowSuite) TestMFADisableIsThrottled() {
	user, totpSecret, client := s.mustCreateMFAUser()
	csrfToken, csrfCookie := fetchCSRFToken(s.T(), s.httpClient, "http://localhost:8080/oauth/login")

	// Reach an authenticated session by completing MFA properly.
	pendingID := s.mustReachMFAStep(user, client, csrfToken, csrfCookie)
	validCode, err := generateTOTPCode(totpSecret)
	s.Require().NoError(err)
	jar, err := cookiejar.New(nil)
	s.Require().NoError(err)
	authed := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp := s.postFormOn(authed, "http://localhost:8080/oauth/mfa", csrfToken, csrfCookie, url.Values{
		"pending_id": {pendingID},
		"code":       {validCode},
	})
	resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode, "MFA login should succeed")

	// A successful verification clears the count, so the full burst is available
	// for the disable endpoint -- which is the behaviour we want to confirm.
	var throttled bool
	for i := 0; i <= mfaAttemptBurst; i++ {
		resp := s.postFormOn(authed, "http://localhost:8080/oauth/mfa-disable", csrfToken, csrfCookie, url.Values{
			"password": {user.Password},
			"code":     {"000000"},
		})
		if resp.StatusCode == http.StatusTooManyRequests {
			throttled = true
		}
		resp.Body.Close()
	}
	s.Require().True(throttled,
		"guessing the disable code must be bounded per account; succeeding there removes MFA entirely")

	// And MFA is still on.
	after, err := s.datastore.Q.GetUserMFAStatus(s.T().Context(), user.ID)
	s.Require().NoError(err)
	s.Require().True(after.MfaEnabled, "MFA must not have been disabled by guessing")
}

// postFormOn is postWithCSRF against a caller-supplied client, so a test can use
// one that carries a session.
func (s *OAuthFlowSuite) postFormOn(client *http.Client, postURL, token string, cookie *http.Cookie, form url.Values) *http.Response {
	s.T().Helper()
	form.Set("csrf_token", token)
	req, err := http.NewRequest(http.MethodPost, postURL, strings.NewReader(form.Encode()))
	s.Require().NoError(err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp, err := client.Do(req)
	s.Require().NoError(err)
	return resp
}
