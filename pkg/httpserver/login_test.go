package httpserver

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/eswan18/identity/pkg/config"
	"github.com/eswan18/identity/pkg/db"
	"github.com/eswan18/identity/pkg/email"
	"github.com/eswan18/identity/pkg/storage"
	"github.com/eswan18/identity/pkg/store"
)

// testJWTECPrivateKey is a throwaway EC key used only to satisfy Server construction
// in hermetic (non-integration) tests; it signs nothing meaningful here.
const testJWTECPrivateKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEICQMNHONu2Sud2tu6jgOZs3LIj5yOZr89NBMLYiyqBK/oAoGCCqGSM49
AwEHoUQDQgAERCHWHrX20emk31HypGNgptwBjdZOyBybV/9BLTbJPj8UsZ/46ri5
/eFKkRfNApxFU/5lk1RGQJqt8t0GvkkJdw==
-----END EC PRIVATE KEY-----`

// newHermeticTestServer builds a *Server without a real database connection.
// sql.Open never dials, so this only fails (fast) the moment a handler actually
// issues a query against 127.0.0.1 on a closed local port -- e.g. "connection
// refused" in single-digit milliseconds, never a slow OS-level TCP timeout.
// That's sufficient to exercise validateOAuthClientRedirect's failure path,
// which is exactly the "unknown/unregistered client" case this test targets;
// it does not need to distinguish that from "row not found".
func newHermeticTestServer(t *testing.T) *Server {
	t.Helper()
	sqlDB, err := sql.Open("pgx", "postgres://user:pass@127.0.0.1:1/db?sslmode=disable")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { sqlDB.Close() })

	ds := &store.Store{DB: sqlDB, Q: db.New(sqlDB)}
	cfg := &config.Config{
		JWTPrivateKey: testJWTECPrivateKey,
		JWTIssuer:     "test-issuer",
	}
	return New(cfg, ds, email.NewLogSender(), storage.NewLogStorage())
}

// TestHandleLoginGet_DoesNotOpenRedirectOnUnvalidatedRedirectURI is a regression
// test for an open redirect: previously, when code_challenge_method was present
// but not "S256", HandleLoginGet redirected straight to the raw redirect_uri
// query parameter without ever checking that it belonged to the registered
// client. An attacker could send
//
//	GET /oauth/login?client_id=whatever&redirect_uri=https://evil.example/cb&code_challenge_method=plain
//
// and get bounced to redirect_uri with OAuth-looking error params attached.
// The fix validates client_id + redirect_uri via validateOAuthClientRedirect
// before ever redirecting there, mirroring HandleOauthAuthorize / HandleConsentPost.
// Since the client_id here is unregistered (and the backing "database" is
// unreachable), validation must fail and the handler must render the local
// error page instead of issuing a 302 to the attacker-controlled host.
func TestHandleLoginGet_DoesNotOpenRedirectOnUnvalidatedRedirectURI(t *testing.T) {
	s := newHermeticTestServer(t)

	const evilRedirect = "https://evil.example/cb"
	req := httptest.NewRequest(http.MethodGet,
		"/oauth/login?client_id=some-client&redirect_uri="+evilRedirect+
			"&code_challenge_method=plain&state=xyz", nil)
	rec := httptest.NewRecorder()

	s.HandleLoginGet(rec, req)

	if rec.Code == http.StatusFound {
		loc := rec.Header().Get("Location")
		t.Fatalf("HandleLoginGet must not redirect to an unvalidated redirect_uri; got %d Location=%q", rec.Code, loc)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Fatalf("expected no Location header on the local error response, got %q", loc)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 (local login error page), got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Only S256 code challenge method is supported") {
		t.Fatalf("expected error page to include the invalid_request error message, got body: %s", body)
	}
}

// TestHandleLoginGet_NoRedirectURIStillRendersLocalError is a sanity check that the
// pre-existing "no redirect_uri" branch continues to render the local error page
// (unchanged behavior).
func TestHandleLoginGet_NoRedirectURIStillRendersLocalError(t *testing.T) {
	s := newHermeticTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth/login?code_challenge_method=plain", nil)
	rec := httptest.NewRecorder()

	s.HandleLoginGet(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 (local login error page), got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Fatalf("expected no Location header, got %q", loc)
	}
}

// TestSetSessionCookie_SecureFlagFollowsIssuerScheme is a regression test: the
// session cookie's Secure attribute used to be derived from
// strings.HasPrefix(config.HTTPAddress, "https://"), but HTTPAddress is the local
// listen address passed to http.Server.Addr (e.g. ":8000") -- never "https://..." --
// so Secure could never be true even in production behind a TLS-terminating proxy.
// It's now derived from the scheme of JWTIssuer, the service's public base URL.
func TestSetSessionCookie_SecureFlagFollowsIssuerScheme(t *testing.T) {
	tests := []struct {
		name       string
		httpAddr   string
		jwtIssuer  string
		wantSecure bool
	}{
		{
			name:       "production: TLS-terminated behind proxy, listen addr is plain :port",
			httpAddr:   ":8000",
			jwtIssuer:  "https://identity.example.com",
			wantSecure: true,
		},
		{
			name:       "local dev over plain HTTP",
			httpAddr:   ":8000",
			jwtIssuer:  "http://localhost:8000",
			wantSecure: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{config: &config.Config{
				HTTPAddress: tt.httpAddr,
				JWTIssuer:   tt.jwtIssuer,
			}}

			rec := httptest.NewRecorder()
			s.setSessionCookie(rec, Session{ID: "some-session-id"})

			cookies := rec.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatalf("expected exactly one cookie, got %d", len(cookies))
			}
			if got := cookies[0].Secure; got != tt.wantSecure {
				t.Errorf("session_id cookie Secure = %v, want %v (HTTPAddress=%q JWTIssuer=%q)",
					got, tt.wantSecure, tt.httpAddr, tt.jwtIssuer)
			}
			if !cookies[0].HttpOnly {
				t.Error("session_id cookie must remain HttpOnly")
			}
		})
	}
}
