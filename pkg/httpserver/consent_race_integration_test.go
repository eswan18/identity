//go:build integration

package httpserver

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/eswan18/identity/pkg/db"
	"github.com/google/uuid"
)

// The race between a code exchange storing tokens and the user disconnecting
// the app, run for real against Postgres in both orders. The exchange's
// insert (InsertTokenIfConsented) takes FOR SHARE on the consent row; the
// disconnect deletes that row and then revokes the user's tokens for the
// client, in one transaction. Whichever gets the row first, the client must
// end up with no live token.

// waitForLockWait waits until some backend is blocked on a lock while running
// a statement containing fragment, i.e. the concurrent side has reached the
// point under test and is waiting for the other.
func (s *OAuthFlowSuite) waitForLockWait(fragment string) {
	s.T().Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var n int
		s.Require().NoError(s.datastore.DB.QueryRowContext(s.T().Context(), `
			SELECT count(*) FROM pg_stat_activity
			WHERE wait_event_type = 'Lock' AND query LIKE '%' || $1 || '%'`, fragment).Scan(&n))
		if n > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.FailNow("timed out waiting for a statement to block on a lock", fragment)
}

// raceSetup is a user, an untrusted client and the user's consent for it.
func (s *OAuthFlowSuite) raceSetup(name string) (UserWithPassword, db.OauthClient) {
	client := s.mustRegisterOAuthClient(s.connectedAppsClientParams(name))
	user := s.newTestUser()
	s.Require().NoError(s.datastore.Q.UpsertUserConsent(s.T().Context(), db.UpsertUserConsentParams{
		UserID: user.ID, ClientID: client.ID, Resource: client.DefaultResource, Scopes: []string{"openid"},
	}))
	return user, client
}

// liveTokens is how many unrevoked token rows user has for client.
func (s *OAuthFlowSuite) liveTokens(user UserWithPassword, client db.OauthClient) int {
	s.T().Helper()
	var n int
	s.Require().NoError(s.datastore.DB.QueryRowContext(s.T().Context(),
		`SELECT count(*) FROM oauth_tokens WHERE user_id = $1 AND client_id = $2 AND revoked_at IS NULL`,
		user.ID, client.ID).Scan(&n))
	return n
}

// The exchange's insert locks the consent first: the disconnect waits for it
// to commit, then revokes the token it just stored.
func (s *OAuthFlowSuite) TestConsentRace_InsertFirstThenDisconnectRevokesIt() {
	ctx := s.T().Context()
	user, client := s.raceSetup("Race Insert First")

	// The exchange's insert, in a transaction left open so its FOR SHARE lock
	// is held while the disconnect starts.
	tx, err := s.datastore.DB.BeginTx(ctx, nil)
	s.Require().NoError(err)
	defer tx.Rollback()
	inserted, err := s.datastore.Q.WithTx(tx).InsertTokenIfConsented(ctx, db.InsertTokenIfConsentedParams{
		AccessToken:      sql.NullString{String: uuid.NewString(), Valid: true},
		RefreshToken:     sql.NullString{String: s.mustGenerateRandomString(32), Valid: true},
		UserID:           user.ID,
		ClientID:         client.ID,
		Scope:            []string{"openid"},
		ExpiresAt:        time.Now().Add(time.Hour),
		RefreshExpiresAt: sql.NullTime{Time: time.Now().Add(24 * time.Hour), Valid: true},
		Resource:         client.DefaultResource,
		FamilyID:         uuid.NullUUID{UUID: uuid.New(), Valid: true},
		ConsentResource:  client.DefaultResource,
	})
	s.Require().NoError(err, "the consent is there, so the insert goes ahead")

	type result struct {
		disconnected bool
		err          error
	}
	done := make(chan result, 1)
	go func() {
		ok, err := s.server.disconnectApp(ctx, user.ID, client.ID)
		done <- result{ok, err}
	}()

	// The disconnect blocks deleting the locked consent row.
	s.waitForLockWait("DELETE FROM oauth_user_consents")
	select {
	case <-done:
		s.FailNow("the disconnect must wait for the insert's lock")
	default:
	}

	s.Require().NoError(tx.Commit())
	var r result
	select {
	case r = <-done:
	case <-time.After(10 * time.Second):
		s.FailNow("the disconnect never finished")
	}
	s.Require().NoError(r.err)
	s.True(r.disconnected)

	row := s.tokenRow(inserted.RefreshToken.String)
	s.True(row.RevokedAt.Valid, "the token committed under the lock is revoked by the disconnect")
	s.Equal("user_disconnected", row.RevokedReason.String)
	s.Zero(s.liveTokens(user, client))
	s.False(s.hasConsent(user, client))
}

// The disconnect deletes the consent first: the real code exchange, arriving
// meanwhile, waits for it to commit, then finds no consent and is refused.
func (s *OAuthFlowSuite) TestConsentRace_DisconnectFirstThenExchangeRefused() {
	ctx := s.T().Context()
	user, client := s.raceSetup("Race Disconnect First")
	scv := s.mustCreateStateAndCodeVerifier()
	code := s.mustGenerateRandomString(32)
	s.Require().NoError(s.datastore.Q.InsertAuthorizationCode(ctx, db.InsertAuthorizationCodeParams{
		Code:                code,
		UserID:              user.ID,
		ClientID:            client.ID,
		RedirectUri:         client.RedirectUris[0],
		Scope:               []string{"openid"},
		CodeChallenge:       sql.NullString{String: scv.CodeChallenge, Valid: true},
		CodeChallengeMethod: sql.NullString{String: "S256", Valid: true},
		ExpiresAt:           time.Now().Add(5 * time.Minute),
		Resource:            client.DefaultResource,
	}))

	// The disconnect's first step, in a transaction left open: the consent
	// row is deleted but not yet committed.
	tx, err := s.datastore.DB.BeginTx(ctx, nil)
	s.Require().NoError(err)
	defer tx.Rollback()
	q := s.datastore.Q.WithTx(tx)
	deleted, err := q.DeleteUserConsentsForUserClient(ctx, db.DeleteUserConsentsForUserClientParams{
		UserID: user.ID, ClientID: client.ID,
	})
	s.Require().NoError(err)
	s.Require().EqualValues(1, deleted)

	type result struct {
		status int
		body   map[string]any
		err    error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := s.httpClient.PostForm(testBaseURL+"/oauth/token", exchangeForm(client, code, scv, nil))
		if err != nil {
			done <- result{err: err}
			return
		}
		defer resp.Body.Close()
		var body map[string]any
		err = json.NewDecoder(resp.Body).Decode(&body)
		done <- result{status: resp.StatusCode, body: body, err: err}
	}()

	// The exchange blocks taking FOR SHARE on the deleted-but-uncommitted row.
	s.waitForLockWait("INSERT INTO oauth_tokens")

	// The rest of the disconnect, then commit.
	_, err = q.RevokeUserClientTokens(ctx, db.RevokeUserClientTokensParams{
		UserID: user.ID, ClientID: client.ID, Reason: string(revokedUserDisconnected),
	})
	s.Require().NoError(err)
	s.Require().NoError(tx.Commit())

	var r result
	select {
	case r = <-done:
	case <-time.After(10 * time.Second):
		s.FailNow("the exchange never finished")
	}
	s.Require().NoError(r.err)
	s.Equal(http.StatusBadRequest, r.status, "%v", r.body)
	s.Equal("invalid_grant", r.body["error"])

	var n int
	s.Require().NoError(s.datastore.DB.QueryRowContext(ctx,
		`SELECT count(*) FROM oauth_tokens WHERE user_id = $1 AND client_id = $2`, user.ID, client.ID).Scan(&n))
	s.Zero(n, "no token was stored")
}
