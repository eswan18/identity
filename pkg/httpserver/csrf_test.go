package httpserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// okHandler is a trivial next-handler that records it was reached and writes 200.
func okHandler(reached *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*reached = true
		w.WriteHeader(http.StatusOK)
	})
}

// newCSRFFormPost builds a urlencoded POST carrying the given cookie/form token
// values. Empty string means "omit".
func newCSRFFormPost(cookieToken, formToken string) *http.Request {
	body := ""
	if formToken != "" {
		body = "csrf_token=" + formToken + "&foo=bar"
	} else {
		body = "foo=bar"
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/change-password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookieToken != "" {
		req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: cookieToken})
	}
	return req
}

func TestCSRFMiddleware_MissingToken403(t *testing.T) {
	s := newHermeticTestServer(t)
	reached := false
	h := s.csrfMiddleware(okHandler(&reached))

	// No cookie, no form field.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, newCSRFFormPost("", ""))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing token: expected 403, got %d", rec.Code)
	}
	if reached {
		t.Fatal("missing token: next handler must not be reached")
	}
}

func TestCSRFMiddleware_CookiePresentFormMissing403(t *testing.T) {
	s := newHermeticTestServer(t)
	reached := false
	h := s.csrfMiddleware(okHandler(&reached))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, newCSRFFormPost("tok-abc", ""))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("form missing: expected 403, got %d", rec.Code)
	}
	if reached {
		t.Fatal("form missing: next handler must not be reached")
	}
}

func TestCSRFMiddleware_Mismatch403(t *testing.T) {
	s := newHermeticTestServer(t)
	reached := false
	h := s.csrfMiddleware(okHandler(&reached))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, newCSRFFormPost("cookie-token", "different-form-token"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("mismatch: expected 403, got %d", rec.Code)
	}
	if reached {
		t.Fatal("mismatch: next handler must not be reached")
	}
}

func TestCSRFMiddleware_MatchPasses(t *testing.T) {
	s := newHermeticTestServer(t)
	reached := false
	h := s.csrfMiddleware(okHandler(&reached))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, newCSRFFormPost("matching-token", "matching-token"))
	if rec.Code != http.StatusOK {
		t.Fatalf("match: expected 200, got %d", rec.Code)
	}
	if !reached {
		t.Fatal("match: next handler must be reached")
	}
}

func TestCSRFMiddleware_SafeMethodsNeverChecked(t *testing.T) {
	s := newHermeticTestServer(t)
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		reached := false
		h := s.csrfMiddleware(okHandler(&reached))
		// No cookie, no form token whatsoever.
		req := httptest.NewRequest(method, "/oauth/change-password", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if !reached {
			t.Fatalf("%s: safe method must pass through without a CSRF token", method)
		}
		if rec.Code == http.StatusForbidden {
			t.Fatalf("%s: safe method must not be rejected with 403", method)
		}
	}
}

// TestCSRFMiddleware_ExemptRouteNotBlocked verifies that the machine OAuth endpoint
// /oauth/token, which is deliberately outside the CSRF-protected route group, is not
// rejected for lacking a CSRF token. It is routed through the full server router so
// the actual middleware wiring in registerRoutes is exercised. The hermetic server
// has no reachable DB, so the token handler may fail for other reasons — the only
// thing asserted here is that the failure is NOT the CSRF 403.
func TestCSRFMiddleware_ExemptRouteNotBlocked(t *testing.T) {
	s := newHermeticTestServer(t)

	body := "grant_type=client_credentials&client_id=x&client_secret=y"
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	s.router.ServeHTTP(rec, req)

	if rec.Code == http.StatusForbidden && strings.Contains(rec.Body.String(), "CSRF") {
		t.Fatalf("/oauth/token must be exempt from CSRF, but got a CSRF 403: %s", rec.Body.String())
	}
}

// TestEnsureCSRFToken_SetsCookieWhenAbsent verifies the read-or-create helper mints a
// token and sets the cookie when the request carries none, and reuses the existing
// cookie value (without resetting it) when one is present.
func TestEnsureCSRFToken_SetsCookieWhenAbsent(t *testing.T) {
	s := newHermeticTestServer(t)

	// Absent -> mint + set.
	req := httptest.NewRequest(http.MethodGet, "/oauth/login", nil)
	rec := httptest.NewRecorder()
	tok := s.ensureCSRFToken(rec, req)
	if tok == "" {
		t.Fatal("expected a non-empty token when none present")
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != csrfCookieName || cookies[0].Value != tok {
		t.Fatalf("expected csrf_token cookie set to %q, got %+v", tok, cookies)
	}
	if !cookies[0].HttpOnly {
		t.Error("csrf_token cookie must be HttpOnly")
	}

	// Present -> reuse, no new Set-Cookie.
	req2 := httptest.NewRequest(http.MethodGet, "/oauth/login", nil)
	req2.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "existing-token"})
	rec2 := httptest.NewRecorder()
	tok2 := s.ensureCSRFToken(rec2, req2)
	if tok2 != "existing-token" {
		t.Fatalf("expected existing token to be reused, got %q", tok2)
	}
	if len(rec2.Result().Cookies()) != 0 {
		t.Fatalf("expected no Set-Cookie when a valid token cookie is already present")
	}
}
