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
