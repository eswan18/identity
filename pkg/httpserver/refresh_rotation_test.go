//go:build integration

package httpserver

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/eswan18/identity/pkg/db"
)

// Refresh-token rotation has to serve two callers that look identical at the
// token endpoint: a browser whose parallel requests all crossed the access
// token's expiry together, and someone replaying a token that should be dead.
// The first must not be logged out; the second must lose the whole session.

// refresh posts a refresh_token grant and hands back the raw response, so a
// test can assert on a failure as easily as a success.
func (s *OAuthFlowSuite) refresh(clientID, refreshToken string) (int, TokenResponse) {
	resp, err := s.httpClient.PostForm("http://localhost:8080/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
	})
	s.Require().NoError(err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)

	var parsed TokenResponse
	_ = json.Unmarshal(body, &parsed)
	return resp.StatusCode, parsed
}

func (s *OAuthFlowSuite) newFlowClientParams() db.CreateOAuthClientParams {
	return db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: "", Valid: false},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid", "profile", "email"},
		IsConfidential: false,
		Audience:       "http://localhost:8000",
	}
}

// TestConcurrentRefreshConvergesOnOneToken is the case that motivated the grace
// window. Before it, exactly one of these calls succeeded and the other was told
// its refresh token had already been used — which the browser client read as
// "your session is over", an hour after logging in.
func (s *OAuthFlowSuite) TestConcurrentRefreshConvergesOnOneToken() {
	flow := s.mustCompleteOAuthFlow(s.newFlowClientParams())

	const racers = 4
	statuses := make([]int, racers)
	tokens := make([]TokenResponse, racers)

	var wg sync.WaitGroup
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			statuses[i], tokens[i] = s.refresh(flow.Client.ClientID, flow.TokenResponse.RefreshToken)
		}()
	}
	wg.Wait()

	for i := range racers {
		s.Equalf(http.StatusOK, statuses[i], "racer %d was refused", i)
		s.NotEmptyf(tokens[i].AccessToken, "racer %d got no access token", i)
	}

	// The point is not merely that they all succeeded: they must agree on which
	// refresh token is live. Handing each racer its own would leave several
	// usable refresh tokens per session, which is what rotation exists to avoid.
	for i := 1; i < racers; i++ {
		s.Equalf(tokens[0].RefreshToken, tokens[i].RefreshToken,
			"racer %d got a different refresh token", i)
	}

	// And the token they agree on has to work.
	status, _ := s.refresh(flow.Client.ClientID, tokens[0].RefreshToken)
	s.Equal(http.StatusOK, status)
}

// TestLateRacerFollowsTheChain covers a racer that arrives after the token has
// been rotated more than once. Following only a single hop would hand it a token
// that is itself already revoked.
func (s *OAuthFlowSuite) TestLateRacerFollowsTheChain() {
	flow := s.mustCompleteOAuthFlow(s.newFlowClientParams())
	original := flow.TokenResponse.RefreshToken

	status, second := s.refresh(flow.Client.ClientID, original)
	s.Require().Equal(http.StatusOK, status)
	status, third := s.refresh(flow.Client.ClientID, second.RefreshToken)
	s.Require().Equal(http.StatusOK, status)

	status, late := s.refresh(flow.Client.ClientID, original)
	s.Equal(http.StatusOK, status)
	s.Equal(third.RefreshToken, late.RefreshToken,
		"a late racer should be given the newest live token, not the one that directly replaced its own")
}

// TestReuseOutsideTheWindowKillsTheChain is the security half. Outside the
// window a rotated token is a replay, and the response is to end the whole line
// of descent -- not just the token presented, which is already dead anyway.
func (s *OAuthFlowSuite) TestReuseOutsideTheWindowKillsTheChain() {
	flow := s.mustCompleteOAuthFlow(s.newFlowClientParams())
	original := flow.TokenResponse.RefreshToken

	status, rotated := s.refresh(flow.Client.ClientID, original)
	s.Require().Equal(http.StatusOK, status)

	// Age the revocation past the window rather than sleeping through it: the
	// test should not take ten seconds to make its point.
	s.mustBackdateRevocation(original, refreshReuseGrace+time.Second)

	status, _ = s.refresh(flow.Client.ClientID, original)
	s.Equal(http.StatusBadRequest, status, "a replay outside the window must be refused")

	// The successor is what an attacker would be holding, so refusing the replay
	// while leaving it usable would defeat the point.
	status, _ = s.refresh(flow.Client.ClientID, rotated.RefreshToken)
	s.Equal(http.StatusBadRequest, status,
		"detecting reuse must revoke the rest of the chain, not only the token presented")
}

func (s *OAuthFlowSuite) mustBackdateRevocation(refreshToken string, by time.Duration) {
	_, err := s.datastore.DB.Exec(
		fmt.Sprintf("UPDATE oauth_tokens SET revoked_at = now() - interval '%d seconds' WHERE refresh_token = $1", int(by.Seconds())),
		refreshToken,
	)
	s.Require().NoError(err)
}
