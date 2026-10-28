package httpserver

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eswan18/identity/pkg/config"
)

// routerStatus sends one request through the server's full router, as a client
// at ip behind the Cloudflare Tunnel.
func routerStatus(srv *Server, method, path, ip string) int {
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = "10.0.0.5:4444"
	req.Header.Set("CF-Connecting-IP", ip)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)
	return rec.Code
}

// The protocol endpoints take well over the general 20/min from one IP, since
// that IP may front many users (Claude's backend does). Each must also really
// be routed: a path that 404s here would mean routes.go and
// protocolEndpointPaths had drifted apart and the budget applied to nothing.
func TestProtocolEndpointsGetTheHigherBudget(t *testing.T) {
	srv := newHermeticTestServer(t)
	t.Cleanup(func() { srv.Close() })

	endpoints := []struct{ method, path string }{
		{http.MethodGet, "/.well-known/openid-configuration"},
		{http.MethodGet, "/.well-known/oauth-authorization-server"},
		{http.MethodGet, "/.well-known/jwks.json"},
		{http.MethodPost, "/oauth/token"},
	}
	if len(endpoints) != len(protocolEndpointPaths) {
		t.Fatalf("test covers %d endpoints but protocolEndpointPaths has %d", len(endpoints), len(protocolEndpointPaths))
	}
	for _, ep := range endpoints {
		t.Run(ep.path, func(t *testing.T) {
			if !protocolEndpointPaths[ep.path] {
				t.Fatalf("%s is not in protocolEndpointPaths", ep.path)
			}
			// An address in Claude's shared range, for flavor; any one IP will do.
			const n = 3 * generalRateLimitPerMinute
			for i := range n {
				code := routerStatus(srv, ep.method, ep.path, "160.79.104.1")
				if code == http.StatusTooManyRequests {
					t.Fatalf("request %d of %d was rate limited", i+1, n)
				}
				if code == http.StatusNotFound || code == http.StatusMethodNotAllowed {
					t.Fatalf("%s %s is not routed (status %d)", ep.method, ep.path, code)
				}
			}
			srv.ResetRateLimits()
		})
	}
}

// Everything else, the login form included, keeps the general budget.
func TestLoginKeepsTheGeneralBudget(t *testing.T) {
	srv := newHermeticTestServer(t)
	t.Cleanup(func() { srv.Close() })

	const ip = "203.0.113.50"
	for i := range generalRateLimitPerMinute {
		if code := routerStatus(srv, http.MethodGet, "/oauth/login", ip); code == http.StatusTooManyRequests {
			t.Fatalf("request %d of %d was rate limited", i+1, generalRateLimitPerMinute)
		}
	}
	if code := routerStatus(srv, http.MethodGet, "/oauth/login", ip); code != http.StatusTooManyRequests {
		t.Fatalf("request %d: status %d, want 429", generalRateLimitPerMinute+1, code)
	}
}

// The two budgets are separate buckets: exhausting the login budget leaves the
// token endpoint and metadata reachable from the same IP, and spending the
// protocol budget does not touch the login one.
func TestProtocolAndGeneralBudgetsAreSeparate(t *testing.T) {
	srv := newHermeticTestServer(t)
	t.Cleanup(func() { srv.Close() })

	const ip = "203.0.113.51"
	for range generalRateLimitPerMinute + 1 {
		routerStatus(srv, http.MethodGet, "/oauth/login", ip)
	}
	if code := routerStatus(srv, http.MethodGet, "/oauth/login", ip); code != http.StatusTooManyRequests {
		t.Fatalf("login: status %d, want 429 once its budget is spent", code)
	}
	if code := routerStatus(srv, http.MethodPost, "/oauth/token", ip); code == http.StatusTooManyRequests {
		t.Error("token endpoint was limited by the login budget")
	}
	if code := routerStatus(srv, http.MethodGet, "/.well-known/oauth-authorization-server", ip); code == http.StatusTooManyRequests {
		t.Error("metadata was limited by the login budget")
	}

	const other = "203.0.113.52"
	for range 2 * generalRateLimitPerMinute {
		routerStatus(srv, http.MethodPost, "/oauth/token", other)
	}
	if code := routerStatus(srv, http.MethodGet, "/oauth/login", other); code == http.StatusTooManyRequests {
		t.Error("login was limited by token-endpoint traffic")
	}
}

// The protocol budget is bounded too, at the configured value.
func TestProtocolBudgetIsConfigurable(t *testing.T) {
	if got := protocolRateLimitPerMinute(&config.Config{}); got != config.DefaultProtocolRateLimitPerMinute {
		t.Errorf("zero config: %d, want default %d", got, config.DefaultProtocolRateLimitPerMinute)
	}
	if got := protocolRateLimitPerMinute(&config.Config{ProtocolRateLimitPerMinute: 42}); got != 42 {
		t.Errorf("configured 42: got %d", got)
	}
	if config.DefaultProtocolRateLimitPerMinute <= generalRateLimitPerMinute {
		t.Errorf("default protocol budget %d is not above the general %d", config.DefaultProtocolRateLimitPerMinute, generalRateLimitPerMinute)
	}

	// And it is enforced: a tiny configured budget runs out.
	small := splitRateLimitMiddleware(
		rateLimitMiddleware(newRateLimitStoreForTest(t), 2),
		rateLimitMiddleware(newRateLimitStoreForTest(t), generalRateLimitPerMinute),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	var codes []int
	for range 3 {
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", nil)
		req.RemoteAddr = "203.0.113.53:1"
		rec := httptest.NewRecorder()
		small.ServeHTTP(rec, req)
		codes = append(codes, rec.Code)
	}
	if codes[0] != http.StatusOK || codes[1] != http.StatusOK || codes[2] != http.StatusTooManyRequests {
		t.Errorf("statuses with a protocol budget of 2: %v, want [200 200 429]", codes)
	}
}

func newRateLimitStoreForTest(t *testing.T) *rateLimitStore {
	t.Helper()
	s := newRateLimitStore(ipEntryTTL)
	t.Cleanup(s.Stop)
	return s
}
