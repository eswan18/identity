package httpserver

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestLiveAccessTokenFailsClosedOnDatabaseError pins the contract every caller
// depends on: when the revocation check cannot be performed, that is an error,
// never a quiet "not revoked".
//
// newHermeticTestServer points at a closed port, so any query fails fast --
// which is precisely the condition the admin middleware used to treat as
// permission to continue.
func TestLiveAccessTokenFailsClosedOnDatabaseError(t *testing.T) {
	srv := newHermeticTestServer(t)

	_, live, err := srv.liveAccessToken(t.Context(), "some-jti")
	if err == nil {
		t.Fatal("liveAccessToken returned no error against an unreachable database; " +
			"callers rely on the error to fail closed")
	}
	if live {
		t.Error("liveAccessToken reported the token live despite failing to check")
	}
}

// TestLiveAccessTokenEmptyJTI covers the case two of the three call sites used to
// skip entirely. A validly-signed token with no jti cannot be produced by this
// service, so treating it as live would be guessing in the unsafe direction.
func TestLiveAccessTokenEmptyJTI(t *testing.T) {
	srv := newHermeticTestServer(t)

	_, live, err := srv.liveAccessToken(t.Context(), "")
	if err != nil {
		t.Fatalf("empty jti should not be an error, got %v", err)
	}
	if live {
		t.Error("an empty jti must not be treated as a live token")
	}
}

// TestAdminAuthMiddlewareFailsClosedOnDatabaseError is the regression test for
// the fail-open.
//
// The token here is genuinely signed and carries the required scope, so every
// check that does not need the database passes. Only the revocation lookup
// fails. Before this change the middleware logged the error and called the next
// handler; it must now refuse.
func TestAdminAuthMiddlewareFailsClosedOnDatabaseError(t *testing.T) {
	srv := newHermeticTestServer(t)

	token, _, err := srv.jwtGenerator.GenerateAccessToken(
		"11111111-1111-1111-1111-111111111111",
		"someone",
		"someone@example.com",
		"test-audience",
		true,
		[]string{"admin:users:read"},
		time.Hour,
	)
	if err != nil {
		t.Fatalf("could not generate a test token: %v", err)
	}

	reached := false
	handler := srv.AdminAuthMiddleware("admin:users:read")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			w.WriteHeader(http.StatusOK)
		}),
	)

	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if reached {
		t.Error("the admin handler ran despite the revocation check failing; " +
			"an unverifiable token must not reach a privileged handler")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d: a failed revocation check is a server error, not a pass",
			rec.Code, http.StatusInternalServerError)
	}
}
