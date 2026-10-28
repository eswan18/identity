//go:build integration

package httpserver

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/eswan18/identity/pkg/db"
	"github.com/google/uuid"
)

// Refresh-token reuse detection (issue #144): families, revocation reasons,
// family revocation on reuse, and the family's absolute lifetime.

// refreshResult is a refresh grant's outcome, read straight off the handler.
type refreshResult struct {
	status int
	tokens TokenResponse
	err    string // the OAuth error code, on failure
}

// refreshDirect posts a refresh grant to the handler directly, bypassing the
// router so the rate limiter plays no part.
func (s *OAuthFlowSuite) refreshDirect(client db.OauthClient, refreshToken string) refreshResult {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {client.ClientID},
	}
	if client.IsConfidential {
		form.Set("client_secret", client.ClientSecret.String)
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.server.HandleOauthToken(rec, req)

	result := refreshResult{status: rec.Code}
	if rec.Code == http.StatusOK {
		s.NoError(json.Unmarshal(rec.Body.Bytes(), &result.tokens))
	} else {
		var body map[string]string
		s.NoError(json.Unmarshal(rec.Body.Bytes(), &body))
		result.err = body["error"]
	}
	return result
}

// mustRefresh refreshes and requires success.
func (s *OAuthFlowSuite) mustRefresh(client db.OauthClient, refreshToken string) TokenResponse {
	s.T().Helper()
	result := s.refreshDirect(client, refreshToken)
	s.Require().Equal(http.StatusOK, result.status, "refresh failed: %s", result.err)
	return result.tokens
}

// requireInvalidGrant refreshes and requires the answer for a dead refresh
// token: 400 invalid_grant, never any other code.
func (s *OAuthFlowSuite) requireInvalidGrant(client db.OauthClient, refreshToken, msg string) {
	s.T().Helper()
	result := s.refreshDirect(client, refreshToken)
	s.Equal(http.StatusBadRequest, result.status, msg)
	s.Equal("invalid_grant", result.err, msg)
}

// tokenRow reads the row for a refresh token, revoked or not.
func (s *OAuthFlowSuite) tokenRow(refreshToken string) db.OauthToken {
	s.T().Helper()
	row, err := s.datastore.Q.GetTokenByRefreshTokenIncludingRevoked(s.T().Context(),
		sql.NullString{String: refreshToken, Valid: true})
	s.Require().NoError(err)
	return row
}

// requireLive asserts a refresh token's row is not revoked.
func (s *OAuthFlowSuite) requireLive(refreshToken, msg string) {
	s.T().Helper()
	row := s.tokenRow(refreshToken)
	s.False(row.RevokedAt.Valid, "%s: revoked with reason %q", msg, row.RevokedReason.String)
}

// requireRevokedFor asserts a refresh token's row is revoked for reason.
func (s *OAuthFlowSuite) requireRevokedFor(refreshToken string, reason revocationReason, msg string) {
	s.T().Helper()
	row := s.tokenRow(refreshToken)
	s.True(row.RevokedAt.Valid, "%s: not revoked", msg)
	s.Equal(sql.NullString{String: string(reason), Valid: true}, row.RevokedReason, msg)
}

// mustInsertRefreshToken stores a token row the way an earlier sign-in would
// have, for cases a sign-in cannot produce (old rows, aged families, a second
// live member of a family). family NULL is a row from before families existed.
func (s *OAuthFlowSuite) mustInsertRefreshToken(client db.OauthClient, userID uuid.UUID, family uuid.NullUUID, refreshExpiresAt time.Time) string {
	s.T().Helper()
	refreshToken := s.mustGenerateRandomString(32)
	_, err := s.datastore.Q.InsertToken(s.T().Context(), db.InsertTokenParams{
		AccessToken:      sql.NullString{String: s.mustGenerateRandomString(16), Valid: true},
		RefreshToken:     sql.NullString{String: refreshToken, Valid: true},
		UserID:           uuid.NullUUID{UUID: userID, Valid: true},
		ClientID:         client.ID,
		Scope:            []string{"openid"},
		TokenType:        sql.NullString{String: "Bearer", Valid: true},
		ExpiresAt:        time.Now().Add(time.Hour),
		RefreshExpiresAt: sql.NullTime{Time: refreshExpiresAt, Valid: true},
		Resource:         testResource("http://localhost:8080"),
		FamilyID:         family,
	})
	s.Require().NoError(err)
	return refreshToken
}

// mustRefreshClientAndUser registers a client (confidential when asked) and a
// user, without a sign-in.
func (s *OAuthFlowSuite) mustRefreshClientAndUser(confidential bool) (db.OauthClient, UserWithPassword) {
	params := db.CreateOAuthClientParams{
		ClientID:        s.mustGenerateRandomString(8),
		Name:            s.mustGenerateRandomString(8),
		RedirectUris:    []string{"http://localhost:8080/callback"},
		AllowedScopes:   []string{"openid", "profile", "email"},
		IsConfidential:  confidential,
		DefaultResource: testResource("http://localhost:8080"),
	}
	if confidential {
		params.ClientSecret = sql.NullString{String: s.mustGenerateRandomString(32), Valid: true}
	}
	client := s.mustRegisterOAuthClient(params)
	user := s.mustRegisterUser(
		s.mustGenerateRandomString(8),
		s.mustGenerateRandomString(8),
		fmt.Sprintf("%s@example.com", s.mustGenerateRandomString(8)),
	)
	return client, user
}

func mustNewFamily(s *OAuthFlowSuite) uuid.NullUUID {
	family, err := newFamilyID()
	s.Require().NoError(err)
	return uuid.NullUUID{UUID: family, Valid: true}
}

// introspectionActive reports whether introspection calls accessToken active.
func (s *OAuthFlowSuite) introspectionActive(accessToken string) bool {
	s.T().Helper()
	introspector, _ := s.mustRefreshClientAndUser(true)
	form := url.Values{
		"token":           {accessToken},
		"token_type_hint": {"access_token"},
		"client_id":       {introspector.ClientID},
		"client_secret":   {introspector.ClientSecret.String},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.server.HandleIntrospect(rec, req)
	s.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	var body map[string]any
	s.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &body))
	return body["active"] == true
}

// userinfoStatus is the status userinfo answers accessToken with.
func (s *OAuthFlowSuite) userinfoStatus(accessToken string) int {
	req := httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rec := httptest.NewRecorder()
	s.server.HandleOauthUserInfo(rec, req)
	return rec.Code
}

// TestRefreshTokenReuseRevokesFamily: rotate twice, then replay the first
// refresh token. The replay is refused, and the family's current tokens -- the
// third refresh token and its access token -- die with it.
func (s *OAuthFlowSuite) TestRefreshTokenReuseRevokesFamily() {
	flow := s.mustCompleteOAuthFlow(db.CreateOAuthClientParams{
		ClientID:        s.mustGenerateRandomString(8),
		Name:            s.mustGenerateRandomString(8),
		RedirectUris:    []string{"http://localhost:8080/callback"},
		AllowedScopes:   []string{"openid", "profile", "email"},
		IsConfidential:  false,
		DefaultResource: testResource("http://localhost:8080"),
	})
	client := flow.Client
	rt0 := flow.TokenResponse.RefreshToken

	// The code exchange started a family, now.
	family := s.tokenRow(rt0).FamilyID
	s.Require().True(family.Valid, "a code exchange must start a family")
	started, ok := familyStartedAt(family.UUID)
	s.Require().True(ok, "family ids are UUIDv7")
	s.WithinDuration(time.Now(), started, time.Minute)

	first := s.mustRefresh(client, rt0)
	second := s.mustRefresh(client, first.RefreshToken)
	s.True(s.introspectionActive(second.AccessToken), "the current access token is live before the replay")
	s.Equal(http.StatusOK, s.userinfoStatus(second.AccessToken))

	for _, rt := range []string{rt0, first.RefreshToken, second.RefreshToken} {
		s.Equal(family, s.tokenRow(rt).FamilyID, "every refresh stays in the sign-in's family")
	}

	s.requireInvalidGrant(client, rt0, "replaying a rotated refresh token")

	s.False(s.introspectionActive(second.AccessToken), "the family's access token must be inactive after reuse")
	s.Equal(http.StatusUnauthorized, s.userinfoStatus(second.AccessToken), "userinfo must refuse the family's access token")
	s.requireInvalidGrant(client, second.RefreshToken, "the family's current refresh token must be dead")

	s.requireRevokedFor(rt0, revokedRotated, "the replayed token keeps its reason")
	s.requireRevokedFor(first.RefreshToken, revokedRotated, "an ancestor keeps its reason")
	s.requireRevokedFor(second.RefreshToken, revokedReuseDetected, "the live token was revoked for reuse")

	// Replaying another spent token later is still refused.
	s.requireInvalidGrant(client, first.RefreshToken, "replaying after the family is gone")
}

// TestRefreshTokenRevokedOtherwiseIsNotReuse: a refresh token that died any way
// but rotation is refused when presented again, and nothing else in its family
// is touched. Each case gives the family a second live member to watch.
func (s *OAuthFlowSuite) TestRefreshTokenRevokedOtherwiseIsNotReuse() {
	future := time.Now().Add(24 * time.Hour)

	cases := []struct {
		name string
		kill func(client db.OauthClient, refreshToken string)
		// expired: the token is inserted already past its refresh expiry.
		expired bool
	}{
		{
			name: "revoked at /oauth/revoke",
			kill: func(client db.OauthClient, refreshToken string) {
				form := url.Values{
					"token":           {refreshToken},
					"token_type_hint": {"refresh_token"},
					"client_id":       {client.ClientID},
					"client_secret":   {client.ClientSecret.String},
				}
				req := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				rec := httptest.NewRecorder()
				s.server.HandleOauthRevoke(rec, req)
				s.Require().Equal(http.StatusOK, rec.Code)
				s.requireRevokedFor(refreshToken, revokedRevoked, "/oauth/revoke records its reason")
			},
		},
		{
			name: "revoked before reasons were recorded (NULL reason)",
			kill: func(_ db.OauthClient, refreshToken string) {
				_, err := s.datastore.DB.ExecContext(s.T().Context(),
					`UPDATE oauth_tokens SET revoked_at = now() WHERE refresh_token = $1`, refreshToken)
				s.Require().NoError(err)
			},
		},
		{
			name: "already revoked for reuse",
			kill: func(_ db.OauthClient, refreshToken string) {
				_, err := s.datastore.Q.RevokeTokenByRefreshToken(s.T().Context(), db.RevokeTokenByRefreshTokenParams{
					RefreshToken: sql.NullString{String: refreshToken, Valid: true},
					Reason:       string(revokedReuseDetected),
				})
				s.Require().NoError(err)
			},
		},
		{
			name:    "rotated, but past its refresh expiry",
			expired: true,
			kill: func(_ db.OauthClient, refreshToken string) {
				n, err := s.datastore.Q.RotateRefreshToken(s.T().Context(), db.RotateRefreshTokenParams{
					RefreshToken: sql.NullString{String: refreshToken, Valid: true},
					FamilyID:     s.tokenRow(refreshToken).FamilyID.UUID,
				})
				s.Require().NoError(err)
				s.Require().EqualValues(1, n)
			},
		},
	}

	for _, c := range cases {
		s.Run(c.name, func() {
			client, user := s.mustRefreshClientAndUser(true)
			family := mustNewFamily(s)
			expiry := future
			if c.expired {
				expiry = time.Now().Add(-time.Hour)
			}
			dead := s.mustInsertRefreshToken(client, user.ID, family, expiry)
			sibling := s.mustInsertRefreshToken(client, user.ID, family, future)

			c.kill(client, dead)
			s.requireInvalidGrant(client, dead, "presenting a dead refresh token")
			s.requireLive(sibling, "the rest of the family must be untouched")
		})
	}
}

// TestPasswordChangeRevokesTokensAsLogout: signing out everywhere records
// "logout", and presenting such a token again is not reuse.
func (s *OAuthFlowSuite) TestPasswordChangeRevokesTokensAsLogout() {
	client, user := s.mustRefreshClientAndUser(false)
	refreshToken := s.mustInsertRefreshToken(client, user.ID, mustNewFamily(s), time.Now().Add(24*time.Hour))

	jar, err := cookiejar.New(nil)
	s.Require().NoError(err)
	browser := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := csrfPostFormLogin(s.T(), browser, "http://localhost:8080/oauth/login", url.Values{
		"username": {user.Username},
		"password": {user.Password},
	})
	s.Require().NoError(err)
	resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)

	newPassword := s.mustGenerateRandomString(16)
	resp, err = csrfPostFormLogin(s.T(), browser, "http://localhost:8080/oauth/change-password", url.Values{
		"current_password": {user.Password},
		"new_password":     {newPassword},
		"confirm_password": {newPassword},
	})
	s.Require().NoError(err)
	resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)

	s.requireRevokedFor(refreshToken, revokedLogout, "a password change signs the user out everywhere")
	s.requireInvalidGrant(client, refreshToken, "presenting a token revoked by logout")
	s.requireRevokedFor(refreshToken, revokedLogout, "and that is not reuse")
}

// TestConcurrentRefreshRevokesTheWinner: several refreshes of one token at
// once. Exactly one succeeds; the others are reuse (no grace window), so the
// winner's freshly minted tokens are revoked too. Repeated, so that both ways
// a loser can find out -- its lookup already sees the token rotated, or its
// own rotation finds it spent -- get exercised.
func (s *OAuthFlowSuite) TestConcurrentRefreshRevokesTheWinner() {
	const rounds = 5
	const racers = 8

	client, user := s.mustRefreshClientAndUser(false)
	for round := range rounds {
		refreshToken := s.mustInsertRefreshToken(client, user.ID, mustNewFamily(s), time.Now().Add(24*time.Hour))

		results := make([]refreshResult, racers)
		var start, done sync.WaitGroup
		start.Add(1)
		for i := range racers {
			done.Add(1)
			go func() {
				defer done.Done()
				start.Wait()
				results[i] = s.refreshDirect(client, refreshToken)
			}()
		}
		start.Done()
		done.Wait()

		var winners []TokenResponse
		for _, r := range results {
			if r.status == http.StatusOK {
				winners = append(winners, r.tokens)
				continue
			}
			s.Equal(http.StatusBadRequest, r.status, "round %d", round)
			s.Equal("invalid_grant", r.err, "round %d: a loser gets invalid_grant", round)
		}
		s.Require().Len(winners, 1, "round %d: exactly one concurrent refresh succeeds", round)

		winner := winners[0]
		s.requireRevokedFor(winner.RefreshToken, revokedReuseDetected, fmt.Sprintf("round %d: the winner's refresh token", round))
		s.False(s.introspectionActive(winner.AccessToken), "round %d: the winner's access token", round)
		s.requireInvalidGrant(client, winner.RefreshToken, "the winner's refresh token is dead")

		// No live token is left in the family: no loser's unissued tokens either.
		var live int
		s.Require().NoError(s.datastore.DB.QueryRowContext(s.T().Context(),
			`SELECT count(*) FROM oauth_tokens WHERE family_id = $1 AND revoked_at IS NULL`,
			s.tokenRow(refreshToken).FamilyID).Scan(&live))
		s.Zero(live, "round %d: the family must have no live token", round)
	}
}

// TestLostRotation drives refuseLostRotation directly: the request minted its
// replacement, then found the presented token already spent. That interleaving
// is a race the concurrency test can hit but not force.
func (s *OAuthFlowSuite) TestLostRotation() {
	future := time.Now().Add(24 * time.Hour)

	s.Run("spent by a concurrent refresh: reuse", func() {
		client, user := s.mustRefreshClientAndUser(false)
		family := mustNewFamily(s)
		presented := s.mustInsertRefreshToken(client, user.ID, family, future)
		winners := s.mustInsertRefreshToken(client, user.ID, family, future)
		_, err := s.datastore.Q.RotateRefreshToken(s.T().Context(), db.RotateRefreshTokenParams{
			RefreshToken: sql.NullString{String: presented, Valid: true},
			FamilyID:     family.UUID,
		})
		s.Require().NoError(err)
		unissued := s.mustInsertRefreshToken(client, user.ID, family, future)

		rec := httptest.NewRecorder()
		s.server.refuseLostRotation(s.T().Context(), rec, client, presented, unissued)

		s.Equal(http.StatusBadRequest, rec.Code)
		s.Contains(rec.Body.String(), `"invalid_grant"`)
		s.requireRevokedFor(winners, revokedReuseDetected, "the winner's tokens")
		s.requireRevokedFor(unissued, revokedReuseDetected, "the unissued tokens")
	})

	s.Run("revoked mid-request: only the unissued tokens go", func() {
		client, user := s.mustRefreshClientAndUser(false)
		family := mustNewFamily(s)
		presented := s.mustInsertRefreshToken(client, user.ID, family, future)
		bystander := s.mustInsertRefreshToken(client, user.ID, family, future)
		_, err := s.datastore.Q.RevokeTokenByRefreshToken(s.T().Context(), db.RevokeTokenByRefreshTokenParams{
			RefreshToken: sql.NullString{String: presented, Valid: true},
			Reason:       string(revokedLogout),
		})
		s.Require().NoError(err)
		unissued := s.mustInsertRefreshToken(client, user.ID, family, future)

		rec := httptest.NewRecorder()
		s.server.refuseLostRotation(s.T().Context(), rec, client, presented, unissued)

		s.Equal(http.StatusBadRequest, rec.Code)
		s.Contains(rec.Body.String(), `"invalid_grant"`)
		s.requireRevokedFor(unissued, revokedLogout, "the unissued tokens die as the presented one did")
		s.requireLive(bystander, "not reuse, so the family is untouched")
	})
}

// TestPreFamilyTokenRefreshes: a token from before families existed (NULL
// family_id) still refreshes, and from then on its lineage is tracked -- so
// replaying it is detected as reuse like any other.
func (s *OAuthFlowSuite) TestPreFamilyTokenRefreshes() {
	client, user := s.mustRefreshClientAndUser(false)
	old := s.mustInsertRefreshToken(client, user.ID, uuid.NullUUID{}, time.Now().Add(24*time.Hour))
	oldRow := s.tokenRow(old)
	s.Require().False(oldRow.FamilyID.Valid)

	refreshed := s.mustRefresh(client, old)

	want := uuid.NullUUID{UUID: legacyFamilyID(oldRow.ID, oldRow.CreatedAt), Valid: true}
	s.Equal(want, s.tokenRow(refreshed.RefreshToken).FamilyID, "the refresh starts a family derived from the old token")
	s.Equal(want, s.tokenRow(old).FamilyID, "and records it on the old token as it spends it")
	s.requireRevokedFor(old, revokedRotated, "the old token was rotated")

	s.requireInvalidGrant(client, old, "replaying the old token")
	s.requireRevokedFor(refreshed.RefreshToken, revokedReuseDetected, "is reuse, and revokes its successor")
}

// TestFamilyAbsoluteLifetime: a family cannot be refreshed past 90 days from
// the sign-in that started it, however recently it was refreshed.
func (s *OAuthFlowSuite) TestFamilyAbsoluteLifetime() {
	future := time.Now().Add(24 * time.Hour)
	day := 24 * time.Hour

	s.Run("a family past its lifetime", func() {
		client, user := s.mustRefreshClientAndUser(false)
		family := uuid.NullUUID{UUID: legacyFamilyID(uuid.New(), time.Now().Add(-familyMaxLifetime-day)), Valid: true}
		refreshToken := s.mustInsertRefreshToken(client, user.ID, family, future)

		s.requireInvalidGrant(client, refreshToken, "refreshing a family past its lifetime")
	})

	s.Run("a pre-family token older than the lifetime", func() {
		client, user := s.mustRefreshClientAndUser(false)
		refreshToken := s.mustInsertRefreshToken(client, user.ID, uuid.NullUUID{}, future)
		_, err := s.datastore.DB.ExecContext(s.T().Context(),
			`UPDATE oauth_tokens SET created_at = now() - interval '91 days' WHERE refresh_token = $1`, refreshToken)
		s.Require().NoError(err)

		s.requireInvalidGrant(client, refreshToken, "refreshing a pre-family token issued 91 days ago")
	})

	s.Run("a family within its lifetime, near the end", func() {
		client, user := s.mustRefreshClientAndUser(false)
		start := time.Now().Add(-familyMaxLifetime + day)
		family := uuid.NullUUID{UUID: legacyFamilyID(uuid.New(), start), Valid: true}
		refreshToken := s.mustInsertRefreshToken(client, user.ID, family, future)

		refreshed := s.mustRefresh(client, refreshToken)
		row := s.tokenRow(refreshed.RefreshToken)
		s.Equal(family, row.FamilyID)
		s.WithinDuration(start.Add(familyMaxLifetime), row.RefreshExpiresAt.Time, time.Second,
			"the new refresh token expires when the family does, not 30 days out")
	})
}
