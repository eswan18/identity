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
// redirects to /oauth/login with a 302, carrying the page asked for as return_to
// so sign-in comes back to it, and never invokes the wrapped handler. This is
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
	if loc := rec.Header().Get("Location"); loc != "/oauth/login?return_to=%2Foauth%2Fchange-password" {
		t.Fatalf("expected redirect to /oauth/login returning to change-password, got %q", loc)
	}
	if reached {
		t.Fatal("next handler must not be reached when unauthenticated")
	}
}

// TestRequireUser_NoSessionRedirectsToLogin verifies the allow-inactive
// middleware performs the same redirect on a missing session. Account settings
// is where a sign-in lands anyway, so it is not carried.
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

// TestRequireActive_DeactivatedUserGoesToAccountSettings verifies that a
// signed-in but deactivated user asking for an active-only page is sent to
// account settings, not back to login (which would bounce them straight back
// here after signing in with that page as return_to), and that an active user
// passes through.
func TestRequireActive_DeactivatedUserGoesToAccountSettings(t *testing.T) {
	s := newHermeticTestServer(t)
	for _, tc := range []struct {
		name     string
		active   bool
		wantCode int
		wantLoc  string
	}{
		{"deactivated", false, http.StatusFound, "/oauth/account-settings"},
		{"active", true, http.StatusOK, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reached := false
			user := db.AuthUser{ID: uuid.New(), Username: "alice", IsActive: tc.active}
			lookup := func(r *http.Request) (db.AuthUser, error) { return user, nil }
			h := s.requireUserWith(requireActive(okHandler(&reached)), lookup)

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/change-password", nil))

			if rec.Code != tc.wantCode {
				t.Fatalf("expected %d, got %d", tc.wantCode, rec.Code)
			}
			if loc := rec.Header().Get("Location"); loc != tc.wantLoc {
				t.Fatalf("expected Location %q, got %q", tc.wantLoc, loc)
			}
			if reached != tc.active {
				t.Fatalf("next reached = %v, want %v", reached, tc.active)
			}
		})
	}
}
