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
		TemplatesDir:  "../../templates",
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
