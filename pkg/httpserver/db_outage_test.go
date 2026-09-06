//go:build integration

package httpserver

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/eswan18/identity/pkg/config"
	"github.com/eswan18/identity/pkg/db"
	"github.com/eswan18/identity/pkg/email"
	"github.com/eswan18/identity/pkg/storage"
	"github.com/eswan18/identity/pkg/store"
)

// A database outage must never be reported as a verdict on the caller's
// credentials or grant. These drive HandleOauthToken end to end, because the
// bug being guarded against was never in writeTokenError -- it was in which
// error code the handler chose before ever reaching it.

// serverWithDeadDatabase builds a Server whose pool is closed, so every query
// fails the way it would while the (external) database is unreachable. It uses
// its own store so the suite's shared one is untouched.
func (s *OAuthFlowSuite) serverWithDeadDatabase() *Server {
	dbURL, err := s.pgContainer.ConnectionString(s.T().Context(), "sslmode=disable")
	s.Require().NoError(err)
	dead, err := store.New(dbURL)
	s.Require().NoError(err)
	s.Require().NoError(dead.DB.Close())

	return New(&config.Config{
		HTTPAddress:   ":0",
		JWTPrivateKey: testJWTPrivateKey,
		JWTIssuer:     "http://localhost:8080",
	}, dead, email.NewLogSender(), storage.NewLogStorage())
}

// postToken calls the handler directly, bypassing the router so the shared rate
// limiter plays no part.
func (s *OAuthFlowSuite) postToken(srv *Server, form url.Values) (int, map[string]string) {
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.HandleOauthToken(rec, req)

	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

// TestDatabaseOutageIsNotBadCredentials covers the failure that fires FIRST in
// an outage. Client authentication runs before either grant handler, and it
// used to fold every lookup error into "invalid client" -- so a client with
// perfectly good credentials was told they were wrong, on the endpoint whose
// answer decides whether a session survives.
func (s *OAuthFlowSuite) TestDatabaseOutageIsNotBadCredentials() {
	status, body := s.postToken(s.serverWithDeadDatabase(), url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"some-refresh-token"},
		"client_id":     {"some-client"},
	})

	s.Equal(http.StatusInternalServerError, status)
	s.Equal("server_error", body["error"])
	s.NotEqual("invalid_client", body["error"], "an outage is not a credentials verdict")
}

// TestDatabaseOutageIsNotAGrantVerdictOnAnyGrant checks the same for the
// authorization_code path. Note this still exercises the CLIENT lookup, not the
// code lookup: client authentication runs first, so with the pool down it is
// what answers. That is the point worth pinning -- whichever grant a client
// asks for, an outage must not come back looking like a verdict on its
// credentials or its grant. The per-lookup distinction underneath is covered by
// TestLookupFailureCode, which can reach errors this route cannot.
func (s *OAuthFlowSuite) TestDatabaseOutageIsNotAGrantVerdictOnAnyGrant() {
	status, body := s.postToken(s.serverWithDeadDatabase(), url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"some-code"},
		"redirect_uri": {"http://localhost:8080/callback"},
		"client_id":    {"some-client"},
	})

	s.Equal(http.StatusInternalServerError, status)
	s.Equal("server_error", body["error"])
	s.NotEqual("invalid_grant", body["error"], "an outage is not a verdict on the code")
}

// postToHandler drives any handler directly, bypassing the router so the shared rate
// limiter plays no part.
func (s *OAuthFlowSuite) postToHandler(h http.HandlerFunc, path string, form url.Values) (int, map[string]string) {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h(rec, req)

	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

// TestOutageOnConfidentialEndpointsIsNotBadCredentials covers introspection and
// revocation, which authenticate the same way the token endpoint does and were
// still calling an unreachable database a credentials failure.
//
// These matter more than their obscurity suggests: a resource server
// introspects on every request it serves, so during an outage it would be told
// its own client credentials were wrong, continuously.
func (s *OAuthFlowSuite) TestOutageOnConfidentialEndpointsIsNotBadCredentials() {
	dead := s.serverWithDeadDatabase()

	for _, tc := range []struct {
		name    string
		path    string
		handler http.HandlerFunc
	}{
		{"introspection", "/oauth/introspect", dead.HandleIntrospect},
		{"revocation", "/oauth/revoke", dead.HandleOauthRevoke},
	} {
		s.Run(tc.name, func() {
			status, body := s.postToHandler(tc.handler, tc.path, url.Values{
				"token":         {"some-token"},
				"client_id":     {"some-client"},
				"client_secret": {"some-secret"},
			})

			s.Equal(http.StatusInternalServerError, status)
			s.Equal("server_error", body["error"])
			s.NotEqual("invalid_client", body["error"],
				"an unreachable database is not a verdict on the caller's credentials")
		})
	}
}

// withTableHidden renames a table for the duration of fn, so queries against it
// fail with a real driver error while the rest of the schema keeps working.
// That is the only way to reach the lookups BELOW client authentication: with
// the whole pool closed, client auth fails first and short-circuits the request.
func (s *OAuthFlowSuite) withTableHidden(table string, fn func()) {
	hidden := table + "_hidden_for_test"
	_, err := s.datastore.DB.Exec("ALTER TABLE " + table + " RENAME TO " + hidden)
	s.Require().NoError(err)
	defer func() {
		_, err := s.datastore.DB.Exec("ALTER TABLE " + hidden + " RENAME TO " + table)
		s.Require().NoError(err, "failed to restore %s -- later tests in this suite will fail", table)
	}()
	fn()
}

// TestRefreshTokenLookupFailureIsNotAGrantVerdict is the test the outage cases
// above cannot be: client authentication succeeds here, so the failure lands on
// GetTokenByRefreshToken. Without it, both call sites of lookupFailure can be
// reverted to a literal "invalid_grant" and the entire suite still passes.
func (s *OAuthFlowSuite) TestRefreshTokenLookupFailureIsNotAGrantVerdict() {
	flow := s.mustCompleteOAuthFlow(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: "", Valid: false},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid", "profile", "email"},
		IsConfidential: false,
		Audience:       "http://localhost:8080",
	})

	s.withTableHidden("oauth_tokens", func() {
		status, body := s.postToken(s.server, url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {flow.TokenResponse.RefreshToken},
			"client_id":     {flow.Client.ClientID},
		})

		s.Equal(http.StatusInternalServerError, status)
		s.Equal("server_error", body["error"])
		// The description must agree with the code, or a client branching on
		// one and a human reading the other reach opposite conclusions.
		s.Equal("Failed to look up refresh token", body["error_description"])
	})
}

// TestAuthorizationCodeLookupFailureIsNotAGrantVerdict is the same for the code
// exchange, where it costs a sign-in rather than a session.
func (s *OAuthFlowSuite) TestAuthorizationCodeLookupFailureIsNotAGrantVerdict() {
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: "", Valid: false},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid", "profile", "email"},
		IsConfidential: false,
		Audience:       "http://localhost:8080",
	})

	s.withTableHidden("oauth_authorization_codes", func() {
		status, body := s.postToken(s.server, url.Values{
			"grant_type":   {"authorization_code"},
			"code":         {"any-code"},
			"redirect_uri": {"http://localhost:8080/callback"},
			"client_id":    {client.ClientID},
		})

		s.Equal(http.StatusInternalServerError, status)
		s.Equal("server_error", body["error"])
		s.Equal("Failed to look up authorization code", body["error_description"])
	})
}

// TestUnknownRefreshTokenStillEndsTheSession guards the other side: the
// discrimination above must not have made a genuinely dead token look
// retryable, or reuse detection stops logging anyone out.
func (s *OAuthFlowSuite) TestUnknownRefreshTokenStillEndsTheSession() {
	flow := s.mustCompleteOAuthFlow(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		ClientSecret:   sql.NullString{String: "", Valid: false},
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid", "profile", "email"},
		IsConfidential: false,
		Audience:       "http://localhost:8080",
	})

	status, body := s.postToken(s.server, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"no-such-token"},
		"client_id":     {flow.Client.ClientID},
	})

	s.Equal(http.StatusBadRequest, status)
	s.Equal("invalid_grant", body["error"])
}
