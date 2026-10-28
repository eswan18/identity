package cimd

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testID = "https://example.com/client"

// testDoc is a valid document for testID.
var testDoc = doc(nil)

// fakeClock is an injectable clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// remoteConn reports a chosen remote address, standing in for a connection to
// that address.
type remoteConn struct {
	net.Conn
	remote net.Addr
}

func (c remoteConn) RemoteAddr() net.Addr { return c.remote }

// harness serves documents from an httptest TLS server while the resolver
// believes it is talking to example.com at a public address. DNS answers and
// the address a connection reports are both under the test's control; no
// packet leaves the machine.
type harness struct {
	t     *testing.T
	srv   *httptest.Server
	clock *fakeClock
	r     *Resolver

	mu      sync.Mutex
	handler http.HandlerFunc
	answers []string // what DNS returns for example.com
	reports string   // if set, the remote address every connection claims

	hits    atomic.Int32 // requests the server saw
	lookups atomic.Int32
	dials   atomic.Int32
}

type harnessOpt func(*testHooks)

func newHarness(t *testing.T, opts ...harnessOpt) *harness {
	t.Helper()
	h := &harness{
		t:       t,
		clock:   &fakeClock{t: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)},
		answers: []string{"160.79.104.10"},
	}
	h.handler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, testDoc)
	}
	h.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.hits.Add(1)
		h.mu.Lock()
		handler := h.handler
		h.mu.Unlock()
		handler(w, r)
	}))
	t.Cleanup(h.srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(h.srv.Certificate())
	hooks := testHooks{
		now:     h.clock.now,
		rootCAs: pool,
		lookup: func(ctx context.Context, host string) ([]net.IPAddr, error) {
			h.lookups.Add(1)
			if host != "example.com" {
				return nil, fmt.Errorf("no such host %s", host)
			}
			h.mu.Lock()
			defer h.mu.Unlock()
			var out []net.IPAddr
			for _, a := range h.answers {
				ip, zone, _ := strings.Cut(a, "%")
				out = append(out, net.IPAddr{IP: net.ParseIP(ip), Zone: zone})
			}
			return out, nil
		},
		dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			h.dials.Add(1)
			var d net.Dialer
			conn, err := d.DialContext(ctx, "tcp", h.srv.Listener.Addr().String())
			if err != nil {
				return nil, err
			}
			h.mu.Lock()
			reports := h.reports
			h.mu.Unlock()
			if reports == "" {
				reports = addr
			}
			remote, err := net.ResolveTCPAddr("tcp", reports)
			if err != nil {
				conn.Close()
				return nil, err
			}
			return remoteConn{Conn: conn, remote: remote}, nil
		},
	}
	for _, o := range opts {
		o(&hooks)
	}
	r, err := newResolver(Config{AllowedHosts: []string{"example.com"}}, hooks)
	if err != nil {
		t.Fatal(err)
	}
	h.r = r
	return h
}

func (h *harness) serve(f http.HandlerFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.handler = f
}

func (h *harness) setAnswers(a ...string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.answers = a
}

func (h *harness) setReports(addr string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.reports = addr
}

func serveJSON(body string, header ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		for i := 0; i+1 < len(header); i += 2 {
			w.Header().Set(header[i], header[i+1])
		}
		fmt.Fprint(w, body)
	}
}

func TestResolveHappyPath(t *testing.T) {
	h := newHarness(t)
	var ua, accept string
	h.serve(func(w http.ResponseWriter, r *http.Request) {
		ua, accept = r.UserAgent(), r.Header.Get("Accept")
		serveJSON(testDoc, "Cache-Control", "public, max-age=300")(w, r)
	})
	md, err := h.r.Resolve(context.Background(), testID)
	if err != nil {
		t.Fatal(err)
	}
	if md.ClientID != testID || md.ClientName != "Example" || len(md.RedirectURIs) != 1 {
		t.Errorf("unexpected metadata %+v", md)
	}
	if !md.FetchedAt.Equal(h.clock.now()) || md.ExpiresAt.Sub(md.FetchedAt) != 5*time.Minute {
		t.Errorf("FetchedAt %v ExpiresAt %v", md.FetchedAt, md.ExpiresAt)
	}
	if ua != DefaultUserAgent {
		t.Errorf("User-Agent = %q", ua)
	}
	if accept != "application/json" {
		t.Errorf("Accept = %q", accept)
	}
	// Callers get copies: changing one does not change the cache.
	md.RedirectURIs[0] = "https://evil.example/cb"
	again, err := h.r.Resolve(context.Background(), testID)
	if err != nil {
		t.Fatal(err)
	}
	if again.RedirectURIs[0] != "https://example.com/cb" {
		t.Error("caller mutation reached the cache")
	}
	if h.hits.Load() != 1 {
		t.Errorf("server hit %d times, want 1", h.hits.Load())
	}
}

func TestResolveRefusesBeforeNetwork(t *testing.T) {
	h := newHarness(t)
	cases := []struct {
		id   string
		want error
	}{
		{"https://claude.ai/oauth/claude-code-client-metadata", ErrHostNotAllowed}, // valid, but not allowed here
		{"https://www.example.com/client", ErrHostNotAllowed},
		{"https://example.com.evil.com/client", ErrHostNotAllowed},
		{"https://10.0.0.1/client", ErrHostNotAllowed},
		{"http://example.com/client", ErrNotClientIDURL},
		{"https://example.com/client?x=1", ErrNotClientIDURL},
		{"https://example.com", ErrNotClientIDURL},
		{"https://example.com:8443/client", ErrNotClientIDURL},
		{"abc123", ErrNotClientIDURL},
	}
	for _, c := range cases {
		_, err := h.r.Resolve(context.Background(), c.id)
		if !errors.Is(err, c.want) {
			t.Errorf("Resolve(%q) = %v, want %v", c.id, err, c.want)
		}
	}
	if n := h.lookups.Load() + h.dials.Load() + h.hits.Load(); n != 0 {
		t.Errorf("refused client_ids caused %d network operations", n)
	}

	// A resolver with no allowed hosts refuses everything, also offline.
	r, err := newResolver(Config{}, testHooks{
		lookup: func(context.Context, string) ([]net.IPAddr, error) { t.Fatal("lookup called"); return nil, nil },
		dial:   func(context.Context, string, string) (net.Conn, error) { t.Fatal("dial called"); return nil, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve(context.Background(), testID); !errors.Is(err, ErrHostNotAllowed) {
		t.Errorf("empty allow-list: %v", err)
	}
}

func TestResolveRefusesSpecialUseAddresses(t *testing.T) {
	h := newHarness(t)
	for _, addr := range forbiddenSamples {
		h.setAnswers(addr)
		_, err := h.r.Resolve(context.Background(), testID)
		if !errors.Is(err, ErrFetch) || !errors.Is(err, ErrForbiddenAddress) {
			t.Errorf("DNS answer %s: err = %v, want ErrFetch and ErrForbiddenAddress", addr, err)
		}
	}
	if h.dials.Load() != 0 || h.hits.Load() != 0 {
		t.Errorf("forbidden answers led to %d dials, %d requests", h.dials.Load(), h.hits.Load())
	}
}

func TestResolveRefusesIfAnyAnswerIsSpecialUse(t *testing.T) {
	h := newHarness(t)
	for _, answers := range [][]string{
		{"160.79.104.10", "10.0.0.1"},
		{"127.0.0.1", "160.79.104.10"},
		{"160.79.104.10", "2606:4700::1", "fd00::1"},
		{"160.79.104.10", "::ffff:169.254.169.254"},
	} {
		h.setAnswers(answers...)
		_, err := h.r.Resolve(context.Background(), testID)
		if !errors.Is(err, ErrForbiddenAddress) {
			t.Errorf("answers %v: err = %v, want ErrForbiddenAddress", answers, err)
		}
	}
	if h.dials.Load() != 0 {
		t.Errorf("%d dials, want 0", h.dials.Load())
	}
}

func TestResolveRefusesNoAnswers(t *testing.T) {
	h := newHarness(t)
	h.setAnswers()
	if _, err := h.r.Resolve(context.Background(), testID); !errors.Is(err, ErrFetch) {
		t.Errorf("err = %v, want ErrFetch", err)
	}
}

func TestResolveRefusesRebinding(t *testing.T) {
	// DNS says public; the connection lands somewhere private. This is what a
	// rebinding resolver beneath the dialer would produce.
	for _, landed := range []string{"10.0.0.5:443", "127.0.0.1:443", "169.254.169.254:443", "[::1]:443", "[fd00::1]:443"} {
		h := newHarness(t)
		h.setReports(landed)
		_, err := h.r.Resolve(context.Background(), testID)
		if !errors.Is(err, ErrForbiddenAddress) {
			t.Errorf("landed on %s: err = %v, want ErrForbiddenAddress", landed, err)
		}
		if h.hits.Load() != 0 {
			t.Errorf("landed on %s: request was sent", landed)
		}
	}
	// A public address DNS never returned is refused too.
	h := newHarness(t)
	h.setReports("8.8.8.8:443")
	if _, err := h.r.Resolve(context.Background(), testID); !errors.Is(err, ErrForbiddenAddress) {
		t.Errorf("landed on an unvetted public address: err = %v", err)
	}
}

func TestResolveDialsVettedAddress(t *testing.T) {
	var dialed []string
	var mu sync.Mutex
	h := newHarness(t)
	inner := h.r.fetcher.dial
	h.r.fetcher.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		dialed = append(dialed, addr)
		mu.Unlock()
		return inner(ctx, network, addr)
	}
	h.setAnswers("160.79.104.10")
	if _, err := h.r.Resolve(context.Background(), testID); err != nil {
		t.Fatal(err)
	}
	if len(dialed) != 1 || dialed[0] != "160.79.104.10:443" {
		t.Errorf("dialed %v, want the vetted IP, never the hostname", dialed)
	}
	if h.lookups.Load() != 1 {
		t.Errorf("%d lookups, want exactly 1", h.lookups.Load())
	}
}

func TestResolveFetchFailures(t *testing.T) {
	big := `{"client_name":"x","pad":"` + strings.Repeat("a", MaxDocumentBytes) + `"}`
	cases := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"404", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }},
		{"500", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }},
		{"201", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(201)
			fmt.Fprint(w, testDoc)
		}},
		{"204", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }},
		{"text/html", serveJSON(testDoc, "Content-Type", "text/html")},
		{"text/plain", serveJSON(testDoc, "Content-Type", "text/plain; charset=utf-8")},
		{"no content type", func(w http.ResponseWriter, r *http.Request) {
			w.Header()["Content-Type"] = nil
			fmt.Fprint(w, testDoc)
		}},
		{"garbled content type", serveJSON(testDoc, "Content-Type", "application/json; ;;=")},
		{"too big with length", serveJSON(big)},
		{"too big chunked", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.(http.Flusher).Flush() // no Content-Length
			fmt.Fprint(w, big)
		}},
	}
	for _, c := range cases {
		h := newHarness(t)
		h.serve(c.handler)
		_, err := h.r.Resolve(context.Background(), testID)
		if !errors.Is(err, ErrFetch) {
			t.Errorf("%s: err = %v, want ErrFetch", c.name, err)
		}
	}
}

func TestResolveAcceptsJSONContentTypes(t *testing.T) {
	for _, ct := range []string{"application/json", "application/json; charset=utf-8", "Application/JSON", "application/vnd.example+json"} {
		h := newHarness(t)
		h.serve(serveJSON(testDoc, "Content-Type", ct))
		if _, err := h.r.Resolve(context.Background(), testID); err != nil {
			t.Errorf("Content-Type %q: %v", ct, err)
		}
	}
}

func TestResolveExactlyMaxSize(t *testing.T) {
	body := testDoc
	body = strings.TrimSuffix(body, "}") + strings.Repeat(" ", MaxDocumentBytes-len(body)) + "}"
	if len(body) != MaxDocumentBytes {
		t.Fatalf("body is %d bytes", len(body))
	}
	h := newHarness(t)
	h.serve(serveJSON(body))
	if _, err := h.r.Resolve(context.Background(), testID); err != nil {
		t.Errorf("a %d-byte document was refused: %v", MaxDocumentBytes, err)
	}
	h = newHarness(t)
	h.serve(serveJSON(body + " "))
	if _, err := h.r.Resolve(context.Background(), testID); !errors.Is(err, ErrFetch) {
		t.Errorf("a %d-byte document: err = %v, want ErrFetch", MaxDocumentBytes+1, err)
	}
}

func TestResolveDoesNotFollowRedirects(t *testing.T) {
	h := newHarness(t)
	var targetHits atomic.Int32
	h.serve(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			targetHits.Add(1)
			serveJSON(testDoc)(w, r)
			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	})
	for range 2 {
		_, err := h.r.Resolve(context.Background(), testID)
		if !errors.Is(err, ErrFetch) || !strings.Contains(err.Error(), "redirects are not followed") {
			t.Errorf("err = %v, want ErrFetch about redirects", err)
		}
	}
	if targetHits.Load() != 0 {
		t.Error("the redirect was followed")
	}
}

func TestResolveTimeout(t *testing.T) {
	h := newHarness(t, func(hk *testHooks) { hk.timeout = 100 * time.Millisecond })
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	h.serve(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	start := time.Now()
	_, err := h.r.Resolve(context.Background(), testID)
	if !errors.Is(err, ErrFetch) {
		t.Errorf("err = %v, want ErrFetch", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("took %v", elapsed)
	}
}

func TestResolveSlowBodyTimesOut(t *testing.T) {
	h := newHarness(t, func(hk *testHooks) { hk.timeout = 100 * time.Millisecond })
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	h.serve(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"client_id":`)
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	if _, err := h.r.Resolve(context.Background(), testID); !errors.Is(err, ErrFetch) {
		t.Errorf("err = %v, want ErrFetch", err)
	}
}

func TestResolveInvalidDocuments(t *testing.T) {
	for _, body := range []string{
		`{not json`,
		`[]`,
		doc(map[string]string{"client_id": `"https://example.com/other"`}),
		doc(map[string]string{"client_secret": `"x"`}),
	} {
		h := newHarness(t)
		h.serve(serveJSON(body))
		if _, err := h.r.Resolve(context.Background(), testID); !errors.Is(err, ErrInvalidDocument) {
			t.Errorf("body %s: err = %v, want ErrInvalidDocument", body, err)
		}
	}
}

func TestCacheTTL(t *testing.T) {
	cases := []struct {
		header string
		want   time.Duration
	}{
		{"", MinCacheTTL},
		{"public", MinCacheTTL},
		{"no-store", MinCacheTTL},
		{"no-cache", MinCacheTTL},
		{"max-age=0", MinCacheTTL},
		{"max-age=60", MinCacheTTL},
		{"max-age=300", 5 * time.Minute},
		{"public, max-age=600", 10 * time.Minute},
		{"MAX-AGE=3600", time.Hour},
		{`max-age="3600"`, time.Hour},
		{"max-age = 3600", time.Hour},
		{"max-age=86400", 24 * time.Hour},
		{"max-age=86401", MaxCacheTTL},
		{"max-age=99999999999999999999", MinCacheTTL}, // unparseable
		{"max-age=-5", MinCacheTTL},
		{"max-age=abc", MinCacheTTL},
		{"s-maxage=3600", MinCacheTTL},
		{"no-store, max-age=3600", time.Hour},
		{"max-age=600,max-age=7200", 10 * time.Minute}, // first wins
	}
	for _, c := range cases {
		if got := cacheTTL(c.header); got != c.want {
			t.Errorf("cacheTTL(%q) = %v, want %v", c.header, got, c.want)
		}
	}
}

func TestResolveCachesForMaxAge(t *testing.T) {
	h := newHarness(t)
	h.serve(serveJSON(testDoc, "Cache-Control", "max-age=600"))
	ctx := context.Background()
	first, err := h.r.Resolve(ctx, testID)
	if err != nil {
		t.Fatal(err)
	}
	if got := first.ExpiresAt.Sub(first.FetchedAt); got != 10*time.Minute {
		t.Errorf("ttl %v, want 10m", got)
	}
	h.clock.advance(9*time.Minute + 59*time.Second)
	if _, err := h.r.Resolve(ctx, testID); err != nil {
		t.Fatal(err)
	}
	if h.hits.Load() != 1 {
		t.Fatalf("refetched before expiry: %d hits", h.hits.Load())
	}
	h.clock.advance(time.Second)
	second, err := h.r.Resolve(ctx, testID)
	if err != nil {
		t.Fatal(err)
	}
	if h.hits.Load() != 2 {
		t.Errorf("did not refetch at expiry: %d hits", h.hits.Load())
	}
	if !second.FetchedAt.After(first.FetchedAt) {
		t.Error("FetchedAt did not move on refetch")
	}
}

func TestResolveClampsMaxAge(t *testing.T) {
	h := newHarness(t)
	h.serve(serveJSON(testDoc, "Cache-Control", "max-age=31536000"))
	md, err := h.r.Resolve(context.Background(), testID)
	if err != nil {
		t.Fatal(err)
	}
	if got := md.ExpiresAt.Sub(md.FetchedAt); got != MaxCacheTTL {
		t.Errorf("ttl %v, want %v", got, MaxCacheTTL)
	}
	h.clock.advance(MaxCacheTTL)
	if _, err := h.r.Resolve(context.Background(), testID); err != nil {
		t.Fatal(err)
	}
	if h.hits.Load() != 2 {
		t.Errorf("%d hits after 24h, want 2", h.hits.Load())
	}
}

func TestResolveDoesNotCacheFailures(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	h.serve(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) })
	if _, err := h.r.Resolve(ctx, testID); !errors.Is(err, ErrFetch) {
		t.Fatalf("err = %v", err)
	}
	h.serve(serveJSON(doc(map[string]string{"client_name": `""`}), "Cache-Control", "max-age=3600"))
	if _, err := h.r.Resolve(ctx, testID); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("err = %v", err)
	}
	h.serve(serveJSON(testDoc))
	if _, err := h.r.Resolve(ctx, testID); err != nil {
		t.Fatalf("a good document after failures: %v", err)
	}
	if h.hits.Load() != 3 {
		t.Errorf("%d hits, want 3 (nothing cached until the good one)", h.hits.Load())
	}

	// Once expired, a failed refetch is an error: a stale document is not
	// served in its place.
	h.clock.advance(MinCacheTTL)
	h.serve(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) })
	if _, err := h.r.Resolve(ctx, testID); !errors.Is(err, ErrFetch) {
		t.Errorf("expired entry with failing refetch: err = %v, want ErrFetch", err)
	}
}

func TestResolveSingleflight(t *testing.T) {
	h := newHarness(t)
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	h.serve(func(w http.ResponseWriter, r *http.Request) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		serveJSON(testDoc)(w, r)
	})

	const n = 50
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := h.r.Resolve(context.Background(), testID)
			errs <- err
		}()
	}
	<-entered
	time.Sleep(50 * time.Millisecond) // let the rest queue on the flight
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("Resolve: %v", err)
		}
	}
	if got := h.hits.Load(); got != 1 {
		t.Errorf("%d concurrent resolves made %d fetches, want 1", n, got)
	}
}

func TestResolveCallerCancellationDoesNotFailOthers(t *testing.T) {
	h := newHarness(t)
	release := make(chan struct{})
	entered := make(chan struct{})
	var once sync.Once
	h.serve(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(entered) })
		<-release
		serveJSON(testDoc)(w, r)
	})

	ctxA, cancelA := context.WithCancel(context.Background())
	errA := make(chan error, 1)
	go func() {
		_, err := h.r.Resolve(ctxA, testID)
		errA <- err
	}()
	<-entered
	errB := make(chan error, 1)
	go func() {
		_, err := h.r.Resolve(context.Background(), testID)
		errB <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancelA()
	if err := <-errA; !errors.Is(err, ErrFetch) || !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled caller: err = %v", err)
	}
	close(release)
	if err := <-errB; err != nil {
		t.Errorf("the other caller failed: %v", err)
	}
	if h.hits.Load() != 1 {
		t.Errorf("%d fetches, want 1", h.hits.Load())
	}
}

func TestCacheIsBounded(t *testing.T) {
	h := newHarness(t)
	for i := range maxCacheEntries + 5 {
		id := fmt.Sprintf("https://example.com/c%d", i)
		h.r.cache[id] = &Metadata{ClientID: id, ExpiresAt: h.clock.now().Add(time.Hour)}
	}
	if _, err := h.r.Resolve(context.Background(), testID); err != nil {
		t.Fatal(err)
	}
	if len(h.r.cache) > maxCacheEntries {
		t.Errorf("cache holds %d entries, max %d", len(h.r.cache), maxCacheEntries)
	}
	if h.r.cached(testID) == nil {
		t.Error("the new entry was not cached")
	}
}

// TestResolveEndToEndLoopback uses the real dialer -- net.Dialer with the
// Control hook -- against the httptest server on 127.0.0.1, through the
// test-only loopback exception. Without the exception the same fetch is
// refused.
func TestResolveEndToEndLoopback(t *testing.T) {
	srv := httptest.NewTLSServer(serveJSON(testDoc, "Cache-Control", "max-age=900"))
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	build := func(permit bool) *Resolver {
		var hooks testHooks
		hooks.permitLoopback = permit
		hooks.rootCAs = pool
		hooks.lookup = func(ctx context.Context, host string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		}
		r, err := newResolver(Config{AllowedHosts: []string{"example.com"}}, hooks)
		if err != nil {
			t.Fatal(err)
		}
		// Keep the production dialer, Control hook and all, but send port
		// 443 to the test server's port.
		real := r.fetcher.dial
		r.fetcher.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, _ := net.SplitHostPort(addr)
			return real(ctx, network, net.JoinHostPort(host, port))
		}
		return r
	}

	md, err := build(true).Resolve(context.Background(), testID)
	if err != nil {
		t.Fatalf("with the loopback exception: %v", err)
	}
	if md.ClientName != "Example" || md.ExpiresAt.Sub(md.FetchedAt) != 15*time.Minute {
		t.Errorf("unexpected metadata %+v", md)
	}

	if _, err := build(false).Resolve(context.Background(), testID); !errors.Is(err, ErrForbiddenAddress) {
		t.Errorf("without the exception: err = %v, want ErrForbiddenAddress", err)
	}
}

func TestProductionResolverRefusesLoopback(t *testing.T) {
	// NewResolver has no way to set the exception; a fetch of a host that
	// resolves to loopback is refused before any connection.
	r, err := NewResolver(Config{AllowedHosts: []string{"localhost"}})
	if err != nil {
		t.Fatal(err)
	}
	if r.fetcher.permitLoopback {
		t.Fatal("NewResolver enabled the loopback exception")
	}
	_, err = r.Resolve(context.Background(), "https://localhost/client")
	if !errors.Is(err, ErrForbiddenAddress) {
		t.Errorf("err = %v, want ErrForbiddenAddress", err)
	}
}
