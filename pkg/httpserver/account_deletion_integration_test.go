//go:build integration

package httpserver

import (
	"database/sql"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Self-service account deletion: the delete page, the deactivate-now /
// erase-later split, the return to a registered app, cancellation by
// reactivating, and the erasure sweep. (Methods on OAuthFlowSuite so CI's
// integration -run pattern picks them up.)

const deleteAccountURL = testBaseURL + "/oauth/delete-account"

func (s *OAuthFlowSuite) mustRegisterDeletionUser() UserWithPassword {
	return s.mustRegisterUser(s.mustGenerateAlphanumericString(10), s.mustGenerateRandomString(16),
		s.mustGenerateAlphanumericString(10)+"@example.com")
}

// postDelete submits the delete form from a signed-in browser.
func (s *OAuthFlowSuite) postDelete(browser *http.Client, form url.Values) (*http.Response, string) {
	s.T().Helper()
	resp, err := csrfPostForm(s.T(), browser, deleteAccountURL, deleteAccountURL, form)
	s.Require().NoError(err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	return resp, string(body)
}

func (s *OAuthFlowSuite) userRow(id any) (isActive bool, deletionRequestedAt sql.NullTime, exists bool) {
	s.T().Helper()
	err := s.datastore.DB.QueryRowContext(s.T().Context(),
		`SELECT is_active, deletion_requested_at FROM auth_users WHERE id = $1`, id).
		Scan(&isActive, &deletionRequestedAt)
	if err == sql.ErrNoRows {
		return false, sql.NullTime{}, false
	}
	s.Require().NoError(err)
	return isActive, deletionRequestedAt, true
}

func (s *OAuthFlowSuite) TestDeleteAccount_WrongPasswordChangesNothing() {
	user := s.mustRegisterDeletionUser()
	browser := s.mustSignInAs(user)

	resp, body := s.postDelete(browser, url.Values{"password": {"not-the-password"}})
	s.Equal(http.StatusUnauthorized, resp.StatusCode)
	s.Contains(body, "Password is incorrect.")

	active, requested, _ := s.userRow(user.ID)
	s.True(active)
	s.False(requested.Valid)
}

func (s *OAuthFlowSuite) TestDeleteAccount_DeactivatesRevokesAndSignsOut() {
	result := s.mustCompleteOAuthFlow(s.connectedAppsClientParams("Deletion"))
	user := result.User
	browser := s.mustSignInAs(user)

	page := s.mustGetPage(browser, deleteAccountURL)
	s.Contains(page, "Delete My Account")
	s.Contains(page, "Back to Account Settings")

	resp, body := s.postDelete(browser, url.Values{"password": {user.Password}})
	s.Require().Equal(http.StatusOK, resp.StatusCode)
	s.Contains(body, "Account Deleted")
	s.Contains(body, time.Now().Add(accountDeletionGracePeriod).UTC().Format("January 2, 2006"))

	active, requested, exists := s.userRow(user.ID)
	s.True(exists)
	s.False(active)
	s.True(requested.Valid)

	var live int
	s.Require().NoError(s.datastore.DB.QueryRowContext(s.T().Context(),
		`SELECT count(*) FROM oauth_tokens WHERE user_id = $1 AND revoked_at IS NULL`, user.ID).Scan(&live))
	s.Zero(live, "every token is revoked")
	var sessions int
	s.Require().NoError(s.datastore.DB.QueryRowContext(s.T().Context(),
		`SELECT count(*) FROM auth_sessions WHERE user_id = $1`, user.ID).Scan(&sessions))
	s.Zero(sessions, "every session is gone")

	// The browser is signed out.
	resp, err := browser.Get(testBaseURL + "/oauth/account-settings")
	s.Require().NoError(err)
	resp.Body.Close()
	s.Equal(http.StatusFound, resp.StatusCode)
}

func (s *OAuthFlowSuite) TestDeleteAccount_ReturnsToRegisteredApp() {
	params := s.connectedAppsClientParams("Footstrike")
	params.RedirectUris = []string{"footstrike://oauth/callback"}
	client := s.mustRegisterOAuthClient(params)
	user := s.mustRegisterDeletionUser()
	browser := s.mustSignInAs(user)

	q := url.Values{"client_id": {client.ClientID}, "redirect_uri": {"footstrike://oauth/callback"}}
	page := s.mustGetPage(browser, deleteAccountURL+"?"+q.Encode())
	s.Contains(page, `name="redirect_uri" value="footstrike://oauth/callback"`)
	s.NotContains(page, "Back to Account Settings")

	form := url.Values{"password": {user.Password}}
	for k, v := range q {
		form[k] = v
	}
	resp, _ := s.postDelete(browser, form)
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	s.Equal("footstrike://oauth/callback?account_deleted=true", resp.Header.Get("Location"))
}

func (s *OAuthFlowSuite) TestDeleteAccount_RefusesUnregisteredReturn() {
	client := s.mustRegisterOAuthClient(s.connectedAppsClientParams("Footstrike"))
	for _, q := range []url.Values{
		{"client_id": {client.ClientID}, "redirect_uri": {"https://evil.example/cb"}},
		{"client_id": {"no-such-client"}, "redirect_uri": {"http://localhost:8080/callback"}},
	} {
		user := s.mustRegisterDeletionUser()
		browser := s.mustSignInAs(user)
		page := s.mustGetPage(browser, deleteAccountURL+"?"+q.Encode())
		s.NotContains(page, `name="redirect_uri"`)

		form := url.Values{"password": {user.Password}}
		for k, v := range q {
			form[k] = v
		}
		resp, body := s.postDelete(browser, form)
		s.Equal(http.StatusOK, resp.StatusCode, "no redirect for %v", q)
		s.Contains(body, "Account Deleted")
	}
}

func (s *OAuthFlowSuite) TestDeleteAccount_SignedOutRoundTripKeepsReturn() {
	user := s.mustRegisterDeletionUser()
	browser := s.newBrowser()
	target := "/oauth/delete-account?client_id=abc&redirect_uri=footstrike%3A%2F%2Foauth%2Fcallback"

	resp, err := browser.Get(testBaseURL + target)
	s.Require().NoError(err)
	resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	s.Equal("/oauth/login?return_to="+url.QueryEscape(target), resp.Header.Get("Location"))

	resp, err = csrfPostFormLogin(s.T(), browser, testBaseURL+"/oauth/login", url.Values{
		"username":  {user.Username},
		"password":  {user.Password},
		"return_to": {target},
	})
	s.Require().NoError(err)
	resp.Body.Close()
	s.Equal(target, resp.Header.Get("Location"))
}

func (s *OAuthFlowSuite) TestDeleteAccount_ReactivatingCancels() {
	user := s.mustRegisterDeletionUser()
	browser := s.mustSignInAs(user)
	resp, _ := s.postDelete(browser, url.Values{"password": {user.Password}})
	s.Require().Equal(http.StatusOK, resp.StatusCode)

	// A deleted (deactivated) user can still sign in here directly.
	browser = s.mustSignInAs(user)
	settings := s.mustGetPage(browser, testBaseURL+"/oauth/account-settings")
	s.Contains(settings, "scheduled for permanent deletion on")

	resp, err := csrfPostForm(s.T(), browser, testBaseURL+"/oauth/account-settings",
		testBaseURL+"/oauth/reactivate-account", url.Values{"password": {user.Password}})
	s.Require().NoError(err)
	resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)

	active, requested, _ := s.userRow(user.ID)
	s.True(active)
	s.False(requested.Valid, "reactivating clears the deletion")
}

func (s *OAuthFlowSuite) TestAccountErasure_ErasesOnlyDueAccounts() {
	ctx := s.T().Context()
	due := s.mustRegisterDeletionUser()
	recent := s.mustRegisterDeletionUser()
	untouched := s.mustRegisterDeletionUser()

	// A consent row, to show the erase cascades through user-owned tables.
	client := s.mustRegisterOAuthClient(s.connectedAppsClientParams("Erasure"))
	_, err := s.datastore.DB.ExecContext(ctx,
		`INSERT INTO oauth_user_consents (user_id, client_id, scopes) VALUES ($1, $2, '{openid}')`,
		due.ID, client.ID)
	s.Require().NoError(err)

	for _, u := range []UserWithPassword{due, recent} {
		s.Require().NoError(s.datastore.Q.RequestUserDeletion(ctx, u.ID))
	}
	_, err = s.datastore.DB.ExecContext(ctx,
		`UPDATE auth_users SET deletion_requested_at = now() - interval '31 days' WHERE id = $1`, due.ID)
	s.Require().NoError(err)

	_, err = s.server.runAccountErasure(ctx, time.Now())
	s.Require().NoError(err)

	_, _, exists := s.userRow(due.ID)
	s.False(exists, "past the grace period: erased")
	var consents int
	s.Require().NoError(s.datastore.DB.QueryRowContext(ctx,
		`SELECT count(*) FROM oauth_user_consents WHERE user_id = $1`, due.ID).Scan(&consents))
	s.Zero(consents)

	_, _, exists = s.userRow(recent.ID)
	s.True(exists, "inside the grace period: kept")
	_, _, exists = s.userRow(untouched.ID)
	s.True(exists)

	// The erased username is free again.
	s.mustRegisterUser(due.Username, s.mustGenerateRandomString(16), due.Email)
}
