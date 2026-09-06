//go:build integration

package httpserver

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// TestVerificationMailBudgetSharedAcrossEndpoints is the point of the change:
// change-email and resend-verification draw on one budget.
//
// Limiting only change-email would leave the relay intact -- point the account's
// address at a victim once, then resend indefinitely -- so this spends the whole
// budget on resend and then asserts that change-email is refused too.
//
// It also asserts the ordering that matters on refusal: the stored address must
// be untouched. Charging the budget after the write would leave the account
// pointing at an unverified address with no link ever sent to it.
func (s *OAuthFlowSuite) TestVerificationMailBudgetSharedAcrossEndpoints() {
	username := s.mustGenerateAlphanumericString(10)
	password := s.mustGenerateAlphanumericString(16)
	originalEmail := fmt.Sprintf("%s@example.com", username)
	user := s.mustRegisterUser(username, password, originalEmail)

	httpClient := s.mustLoginAsUser(username, password)

	// Fetch the CSRF token once and reuse it, rather than re-GETting a form page
	// per request: the double-submit check only compares the cookie against the
	// form value, and this keeps the test clear of the global per-IP limiter.
	csrfToken, _ := fetchCSRFToken(s.T(), httpClient, "http://localhost:8080/oauth/login")

	// Spend the whole budget on resend-verification.
	for i := 1; i <= verificationMailBurst; i++ {
		resp := s.postForm(httpClient, "http://localhost:8080/oauth/resend-verification", url.Values{
			"csrf_token": {csrfToken},
		})
		resp.Body.Close()
		s.Require().Equal(http.StatusFound, resp.StatusCode, "resend %d should have been accepted", i)
		s.Require().Contains(resp.Header.Get("Location"), "success=verification_sent",
			"resend %d should have sent; got %s", i, resp.Header.Get("Location"))
	}

	// One more resend is refused.
	resp := s.postForm(httpClient, "http://localhost:8080/oauth/resend-verification", url.Values{
		"csrf_token": {csrfToken},
	})
	resp.Body.Close()
	s.Require().Contains(resp.Header.Get("Location"), "error=verification_rate_limited",
		"the burst should be spent")

	// And so is change-email, because they share the budget. This is the
	// assertion that would fail if only change-email had been limited.
	newEmail := fmt.Sprintf("%s@example.com", s.mustGenerateAlphanumericString(10))
	resp = s.postForm(httpClient, "http://localhost:8080/oauth/change-email", url.Values{
		"new_email":  {newEmail},
		"password":   {password},
		"csrf_token": {csrfToken},
	})
	defer resp.Body.Close()
	s.Require().Equal(http.StatusTooManyRequests, resp.StatusCode,
		"change-email must draw on the same budget as resend-verification")

	// The refusal must not have moved the address.
	after, err := s.datastore.Q.GetUserByIDIncludingInactive(s.T().Context(), user.ID)
	s.Require().NoError(err)
	s.Require().Equal(originalEmail, after.Email,
		"a refused change-email must leave the stored address untouched")
}

// TestVerificationMailBudgetIsPerAccount asserts one account exhausting its
// budget does not deny another. A global budget would turn this mitigation into
// a denial-of-service against every other user's verification mail.
func (s *OAuthFlowSuite) TestVerificationMailBudgetIsPerAccount() {
	spend := func() *http.Client {
		username := s.mustGenerateAlphanumericString(10)
		password := s.mustGenerateAlphanumericString(16)
		s.mustRegisterUser(username, password, fmt.Sprintf("%s@example.com", username))
		return s.mustLoginAsUser(username, password)
	}

	first := spend()
	token, _ := fetchCSRFToken(s.T(), first, "http://localhost:8080/oauth/login")
	for i := 0; i < verificationMailBurst; i++ {
		resp := s.postForm(first, "http://localhost:8080/oauth/resend-verification", url.Values{
			"csrf_token": {token},
		})
		resp.Body.Close()
	}
	exhausted := s.postForm(first, "http://localhost:8080/oauth/resend-verification", url.Values{
		"csrf_token": {token},
	})
	exhausted.Body.Close()
	s.Require().Contains(exhausted.Header.Get("Location"), "error=verification_rate_limited")

	second := spend()
	secondToken, _ := fetchCSRFToken(s.T(), second, "http://localhost:8080/oauth/login")
	resp := s.postForm(second, "http://localhost:8080/oauth/resend-verification", url.Values{
		"csrf_token": {secondToken},
	})
	defer resp.Body.Close()
	s.Require().Contains(resp.Header.Get("Location"), "success=verification_sent",
		"a second account must have its own budget")
}

// postForm submits a urlencoded form using the client's existing cookie jar,
// without re-fetching a CSRF token. csrfPostForm GETs a form page on every call,
// which doubles the request count and can push a multi-request test into the
// global per-IP limiter.
func (s *OAuthFlowSuite) postForm(client *http.Client, postURL string, form url.Values) *http.Response {
	s.T().Helper()
	req, err := http.NewRequest(http.MethodPost, postURL, strings.NewReader(form.Encode()))
	s.Require().NoError(err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	s.Require().NoError(err)
	return resp
}
