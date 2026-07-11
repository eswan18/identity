package httpserver

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eswan18/identity/pkg/db"
	"github.com/google/uuid"
)

// TestRequireActiveUser_NoSessionRedirectsToLogin verifies that the
// requireActiveUser middleware, when the request carries no session cookie,
// redirects to /oauth/login with a 302 (the exact behavior the account handlers
// previously implemented inline) and never invokes the wrapped handler. This is
// hermetic: doGetUserFromSession fails on the missing cookie before ever touching
// the (unreachable) database.
func TestRequireActiveUser_NoSessionRedirectsToLogin(t *testing.T) {
	s := newHermeticTestServer(t)
	reached := false
	h := s.requireActiveUser(okHandler(&reached))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/oauth/change-password", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302 Found, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/oauth/login" {
		t.Fatalf("expected redirect to /oauth/login, got %q", loc)
	}
	if reached {
		t.Fatal("next handler must not be reached when unauthenticated")
	}
}

// TestRequireUser_NoSessionRedirectsToLogin verifies the allow-inactive
// middleware performs the same redirect on a missing session.
func TestRequireUser_NoSessionRedirectsToLogin(t *testing.T) {
	s := newHermeticTestServer(t)
	reached := false
	h := s.requireUser(okHandler(&reached))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/oauth/account-settings", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302 Found, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/oauth/login" {
		t.Fatalf("expected redirect to /oauth/login, got %q", loc)
	}
	if reached {
		t.Fatal("next handler must not be reached when unauthenticated")
	}
}

// TestRequireUserWith_InjectsUserIntoContext verifies that on a successful lookup
// the middleware stores the resolved user in the request context (retrievable via
// userFromContext) and calls next. It uses requireUserWith with a stub lookup so
// no database is required.
func TestRequireUserWith_InjectsUserIntoContext(t *testing.T) {
	s := newHermeticTestServer(t)
	want := db.AuthUser{ID: uuid.New(), Username: "alice", Email: "alice@example.com"}

	var gotUser db.AuthUser
	var gotOK bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotOK = userFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	lookup := func(r *http.Request) (db.AuthUser, error) { return want, nil }
	h := s.requireUserWith(next, lookup)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/oauth/change-password", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !gotOK {
		t.Fatal("next handler did not find a user in the request context")
	}
	if gotUser.ID != want.ID || gotUser.Username != want.Username {
		t.Fatalf("context user mismatch: got %+v, want %+v", gotUser, want)
	}
}
