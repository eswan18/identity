package httpserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestHandleOauthUserInfo_NoTokenReturns401 is a regression/coverage test for
// OIDC Core §5.3 POST support: with no Authorization header and no
// form/query token, both GET and POST must be rejected the same way, and
// this must hold without ever touching the database (the check happens
// before any token validation or DB lookup).
func TestHandleOauthUserInfo_NoTokenReturns401(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			s := &Server{}
			req := httptest.NewRequest(method, "/oauth/userinfo", nil)
			rec := httptest.NewRecorder()

			s.HandleOauthUserInfo(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
			}
			var body map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("failed to unmarshal response body: %v", err)
			}
			if body["error"] != "invalid_token" {
				t.Errorf("expected error invalid_token, got %q", body["error"])
			}
			// RFC 6750 §3: a Bearer-protected resource returning 401 SHOULD include
			// a WWW-Authenticate header, using the Bearer scheme (not the Basic
			// scheme used by the token/introspect/revoke client-auth endpoints),
			// and it should agree with the JSON body's error/error_description.
			wantAuth := `Bearer error="invalid_token", error_description="Missing or invalid Authorization header"`
			if got := rec.Header().Get("WWW-Authenticate"); got != wantAuth {
				t.Errorf("WWW-Authenticate = %q, want %q", got, wantAuth)
			}
		})
	}
}

// TestHandleOauthUserInfo_InvalidTokenReturns401WithBearerChallenge verifies that
// a syntactically-invalid/unparseable bearer token (which fails JWT validation
// before any database lookup, so this is hermetically testable without a real
// Postgres connection) also gets the RFC 6750 §3 WWW-Authenticate header, with
// the Bearer scheme and an error/error_description matching the JSON body.
func TestHandleOauthUserInfo_InvalidTokenReturns401WithBearerChallenge(t *testing.T) {
	s := newHermeticTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer not-a-valid-jwt")
	rec := httptest.NewRecorder()

	s.HandleOauthUserInfo(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to unmarshal response body: %v", err)
	}
	if body["error"] != "invalid_token" {
		t.Errorf("expected error invalid_token, got %q", body["error"])
	}
	wantAuth := `Bearer error="invalid_token", error_description="Invalid or expired access token"`
	if got := rec.Header().Get("WWW-Authenticate"); got != wantAuth {
		t.Errorf("WWW-Authenticate = %q, want %q", got, wantAuth)
	}
}

// TestUserInfoRoute_POSTRegisteredOutsideCSRFGroup verifies that POST
// /oauth/userinfo is wired up in registerRoutes (OIDC Core §5.3 requires
// UserInfo to support both GET and POST) and, critically, that it is
// reachable WITHOUT a CSRF token. If POST had accidentally been added inside
// the cookie/session CSRF-protected route group instead of the
// machine-endpoints section, this request would be rejected by
// csrfMiddleware (403) before ever reaching the handler; instead we expect
// the handler's own 401 invalid_token (no Authorization header supplied),
// proving the request reached HandleOauthUserInfo directly.
func TestUserInfoRoute_POSTRegisteredOutsideCSRFGroup(t *testing.T) {
	s := newHermeticTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/oauth/userinfo", nil)
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 invalid_token from the handler (not a CSRF 403 or a 404/405 from missing route registration), got %d: %s",
			rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to unmarshal response body: %v", err)
	}
	if body["error"] != "invalid_token" {
		t.Errorf("expected error invalid_token (proving the route reached the handler), got %q", body["error"])
	}
}

// TestHandleOauthUserInfo_TokenResolution exercises the three token-transport
// paths described in OIDC Core §5.3.1 / RFC 6750 without requiring a live
// Postgres connection: it mints a real, validly-signed access token via the
// hermetic server's jwtGenerator, then checks how far each request gets past
// the "resolve the token" step by distinguishing the early
// "Missing or invalid Authorization header" 401 (token never resolved) from
// any later-stage response (token was resolved and handed to
// ValidateToken/the revocation lookup - the hermetic server's Postgres
// connection points at an unreachable address, so those requests fail
// later with a different error, which is exactly the signal this test
// needs: it proves the token reached that stage instead of failing at the
// "no token provided" gate).
func TestHandleOauthUserInfo_TokenResolution(t *testing.T) {
	s := newHermeticTestServer(t)

	accessToken, _, err := s.jwtGenerator.GenerateAccessToken(
		"11111111-1111-1111-1111-111111111111", "someuser", "user@example.com", "aud",
		true, []string{"openid"}, time.Hour,
	)
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}

	const missingHeaderMsg = "Missing or invalid Authorization header"

	assertTokenWasResolved := func(t *testing.T, rec *httptest.ResponseRecorder) {
		t.Helper()
		var body map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err == nil {
			if body["error_description"] == missingHeaderMsg {
				t.Fatalf("token was not resolved from the request; got the no-token 401: %s", rec.Body.String())
			}
		}
	}

	t.Run("POST with Authorization header still works", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/oauth/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		rec := httptest.NewRecorder()

		s.HandleOauthUserInfo(rec, req)

		assertTokenWasResolved(t, rec)
	})

	t.Run("POST with form-body access_token and no Authorization header", func(t *testing.T) {
		form := url.Values{"access_token": {accessToken}}
		req := httptest.NewRequest(http.MethodPost, "/oauth/userinfo", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		s.HandleOauthUserInfo(rec, req)

		assertTokenWasResolved(t, rec)
	})

	t.Run("GET with access_token in the query string is NOT honored", func(t *testing.T) {
		// OIDC discourages the URI-query-parameter method; the fallback is
		// intentionally POST-form-only, so a GET with the token only in the
		// query string must still be rejected as if no token were supplied.
		req := httptest.NewRequest(http.MethodGet, "/oauth/userinfo?access_token="+url.QueryEscape(accessToken), nil)
		rec := httptest.NewRecorder()

		s.HandleOauthUserInfo(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
		}
		var body map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("failed to unmarshal response body: %v", err)
		}
		if body["error_description"] != missingHeaderMsg {
			t.Errorf("expected the no-token error (query param must not be honored), got %q", body["error_description"])
		}
	})
}
