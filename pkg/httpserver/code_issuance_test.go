package httpserver

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eswan18/identity/pkg/db"
)

// TestDenyCodeIssuanceFailsClosedOnUnknownKind is the guard that makes this
// abstraction safe to extend.
//
// The point of checkCodeIssuance is that a precondition added there applies to
// both code-minting paths. The residual risk is the rendering half: someone adds
// a denial kind and forgets a case in denyCodeIssuance. Go does not require
// exhaustive switches, so the default branch has to be the thing that catches
// it -- and it has to deny, not fall through silently.
//
// The cases here are the ones a mistake actually produces. An earlier version of
// this test used only a far-off kind (9999), which passed while the zero value
// -- by far the likelier accident -- panicked: denialInvalidParams was iota 0,
// and it is the one branch that dereferences OAuthError. The test gave
// assurance the code did not deserve.
func TestDenyCodeIssuanceFailsClosedOnUnrenderedKinds(t *testing.T) {
	tests := []struct {
		name   string
		denial *codeIssuanceDenial
	}{
		{
			// The zero value: a denial constructed without setting Kind.
			name:   "zero value",
			denial: &codeIssuanceDenial{},
		},
		{
			name:   "explicitly unspecified",
			denial: &codeIssuanceDenial{Kind: denialUnspecified},
		},
		{
			// A kind added later that no caller renders yet.
			name:   "kind from the future",
			denial: &codeIssuanceDenial{Kind: codeIssuanceDenialKind(9999)},
		},
		{
			// The right kind, but nothing to render with -- the shape that
			// panicked.
			name:   "invalid params with no error attached",
			denial: &codeIssuanceDenial{Kind: denialInvalidParams},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newHermeticTestServer(t)
			denied := false
			redirects := codeIssuanceRedirects{
				ToClient:        func(errorCode, description string) { denied = true },
				Unauthenticated: "/oauth/login",
				Deactivated:     "/oauth/login?error=account_deactivated",
			}

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/oauth/authorize", nil)

			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("denyCodeIssuance panicked (%v); a malformed denial must deny, not crash", r)
				}
			}()
			srv.denyCodeIssuance(rec, req, tt.denial, redirects)

			if !denied {
				t.Error("no response was produced; a denial this code cannot render must still " +
					"deny rather than fall through to issuing a code")
			}
		})
	}
}

// TestDenyCodeIssuanceRoutesEachKind pins where each denial goes, so a future
// edit cannot quietly turn "deactivated" into a client redirect or send an
// unauthenticated user to the wrong place.
func TestDenyCodeIssuanceRoutesEachKind(t *testing.T) {
	tests := []struct {
		name         string
		denial       *codeIssuanceDenial
		wantToClient bool
		wantLocation string
	}{
		{
			name: "invalid params go back to the client per RFC 6749",
			denial: &codeIssuanceDenial{
				Kind:       denialInvalidParams,
				OAuthError: &oauthAuthorizeError{"invalid_scope", "nope"},
			},
			wantToClient: true,
		},
		{
			name:         "no session goes to the login page",
			denial:       &codeIssuanceDenial{Kind: denialNoSession},
			wantLocation: "/oauth/login",
		},
		{
			name:         "a deactivated account is told so",
			denial:       &codeIssuanceDenial{Kind: denialUserInactive},
			wantLocation: "/oauth/login?error=account_deactivated",
		},
		{
			name:         "a failed user lookup is a server error, never a pass",
			denial:       &codeIssuanceDenial{Kind: denialUserLookupFailed},
			wantToClient: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newHermeticTestServer(t)
			toClient := false
			redirects := codeIssuanceRedirects{
				ToClient:        func(errorCode, description string) { toClient = true },
				Unauthenticated: "/oauth/login",
				Deactivated:     "/oauth/login?error=account_deactivated",
			}

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/oauth/authorize", nil)
			srv.denyCodeIssuance(rec, req, tt.denial, redirects)

			if toClient != tt.wantToClient {
				t.Errorf("redirected to client = %v, want %v", toClient, tt.wantToClient)
			}
			if tt.wantLocation != "" && rec.Header().Get("Location") != tt.wantLocation {
				t.Errorf("Location = %q, want %q", rec.Header().Get("Location"), tt.wantLocation)
			}
		})
	}
}

// TestCheckCodeIssuanceRejectsBadParamsBeforeTouchingTheDatabase documents the
// ordering. Parameter validation is pure, so it runs first; against the
// hermetic server (unreachable database) a bad-parameter request must still
// produce the parameter denial rather than a lookup failure.
func TestCheckCodeIssuanceRejectsBadParamsBeforeTouchingTheDatabase(t *testing.T) {
	srv := newHermeticTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize", nil)

	// response_type is wrong, so validateAuthorizeParams rejects it.
	_, denial := srv.checkCodeIssuance(req, testOAuthClient(), "token", "challenge", "S256", []string{"openid"})

	if denial == nil {
		t.Fatal("expected a denial for an unsupported response_type")
	}
	if denial.Kind != denialInvalidParams {
		t.Errorf("Kind = %v, want denialInvalidParams", denial.Kind)
	}
	if denial.OAuthError == nil || denial.OAuthError.Code != "unsupported_response_type" {
		t.Errorf("OAuthError = %+v, want unsupported_response_type", denial.OAuthError)
	}
}

// TestCheckCodeIssuanceRequiresASession covers the next precondition: with valid
// parameters but no session cookie, the denial is denialNoSession.
func TestCheckCodeIssuanceRequiresASession(t *testing.T) {
	srv := newHermeticTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize", nil)

	_, denial := srv.checkCodeIssuance(req, testOAuthClient(), "code", "challenge", "S256", []string{"openid"})

	if denial == nil {
		t.Fatal("expected a denial with no session cookie")
	}
	if denial.Kind != denialNoSession {
		t.Errorf("Kind = %v, want denialNoSession", denial.Kind)
	}
}

// testOAuthClient is a client permissive enough that only the condition under
// test can fail.
func testOAuthClient() db.OauthClient {
	return db.OauthClient{AllowedScopes: []string{"openid", "profile", "email"}}
}
