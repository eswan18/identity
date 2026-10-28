package cimd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"syscall"
	"time"
)

const (
	// FetchTimeout bounds a whole fetch: DNS, connect, TLS, headers and body.
	// Claude allows identity 10 s for the authorization request it is part of.
	FetchTimeout = 5 * time.Second
	// MaxDocumentBytes is the most of a document that is read (CIMD §8.7). A
	// longer body is an error, not a truncation.
	MaxDocumentBytes = 5 * 1024
	// DefaultUserAgent identifies identity's fetcher to the document's host.
	DefaultUserAgent = "identity-cimd-fetcher/1.0 (+https://github.com/eswan18/identity)"
)

// lookupFunc and dialFunc are the network seams. Production uses net's; tests
// substitute fakes so nothing touches the network.
type (
	lookupFunc func(ctx context.Context, host string) ([]net.IPAddr, error)
	dialFunc   func(ctx context.Context, network, addr string) (net.Conn, error)
)

// fetcher retrieves documents. Every field is fixed at construction.
type fetcher struct {
	client         *http.Client
	userAgent      string
	lookup         lookupFunc
	dial           dialFunc
	permitLoopback bool
	timeout        time.Duration
}

// fetched is a successful fetch: the body and the response's Cache-Control.
type fetched struct {
	body         []byte
	cacheControl string
}

func newFetcher(userAgent string, h testHooks) *fetcher {
	f := &fetcher{userAgent: userAgent, permitLoopback: h.permitLoopback, timeout: FetchTimeout}
	if h.timeout > 0 {
		f.timeout = h.timeout
	}
	f.lookup = h.lookup
	if f.lookup == nil {
		f.lookup = net.DefaultResolver.LookupIPAddr
	}
	f.dial = h.dial
	if f.dial == nil {
		d := &net.Dialer{
			Timeout: f.timeout,
			// Checked again just before connect(2), on the address the kernel
			// is about to use. Redundant with guardedDial's own checks today;
			// it keeps the guarantee if guardedDial ever changes.
			Control: func(network, address string, _ syscall.RawConn) error {
				return f.checkHostPort(address)
			},
		}
		f.dial = d.DialContext
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: h.rootCAs}
	transport := &http.Transport{
		// Never a proxy: with one, the dialer would vet the proxy's address
		// rather than the document host's, and the environment could set it.
		Proxy:                 nil,
		DialContext:           f.guardedDial,
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   f.timeout,
		ResponseHeaderTimeout: f.timeout,
		// Each connection is vetted when dialed; not pooling them keeps that
		// true of every request and costs little at one fetch per document per
		// cache lifetime.
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 16 * 1024,
	}
	f.client = &http.Client{
		Transport: transport,
		Timeout:   f.timeout,
		// CIMD §5: MUST NOT follow redirects. Returning the 3xx itself lets
		// fetch report it as a non-200 status without a second request.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return f
}

// forbiddenErr builds the error for a special-use address. It matches both
// ErrFetch's caller-facing kind (added by fetch) and ErrForbiddenAddress.
func forbiddenErr(what string, addr netip.Addr) error {
	return fmt.Errorf("%w: %s %s", ErrForbiddenAddress, what, addr)
}

// checkHostPort refuses an "ip:port" whose ip is special-use or not an IP.
func (f *fetcher) checkHostPort(hostport string) error {
	ap, err := netip.ParseAddrPort(hostport)
	if err != nil {
		return fmt.Errorf("%w: cannot parse dial address %q", ErrForbiddenAddress, hostport)
	}
	if forbidden(ap.Addr(), f.permitLoopback) {
		return forbiddenErr("dialing", ap.Addr())
	}
	return nil
}

// guardedDial is the transport's DialContext. addr is the request's
// "host:port". It resolves the host, refuses if any answer is special-use,
// then dials the vetted IPs themselves (so DNS is not consulted again) and
// checks the connection's remote address before handing it back.
//
// Refusing when any address is bad -- not merely skipping the bad ones -- is
// deliberate: a host that publishes a private address alongside a public one
// is either misconfigured or probing, and neither is a host to fetch from.
func (f *fetcher) guardedDial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip}
	} else {
		answers, err := f.lookup(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolving %s: %w", host, err)
		}
		for _, a := range answers {
			ip, ok := netip.AddrFromSlice(a.IP)
			if !ok {
				return nil, fmt.Errorf("%w: unparseable address for %s", ErrForbiddenAddress, host)
			}
			if a.Zone != "" {
				ip = ip.WithZone(a.Zone)
			}
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("resolving %s: no addresses", host)
	}
	for _, ip := range ips {
		if forbidden(ip, f.permitLoopback) {
			return nil, forbiddenErr("host "+host+" resolves to", ip)
		}
	}

	var errs []error
	for _, ip := range ips {
		target := net.JoinHostPort(ip.Unmap().String(), port)
		conn, err := f.dial(ctx, network, target)
		if err != nil {
			if errors.Is(err, ErrForbiddenAddress) {
				return nil, err
			}
			errs = append(errs, err)
			continue
		}
		if err := f.checkConn(conn, ips); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}
	return nil, errors.Join(errs...)
}

// checkConn verifies that conn's remote address is one of the vetted IPs and
// is not special-use. A dialer that connected somewhere else -- a rebinding
// resolver underneath, a misbehaving custom dialer -- fails here.
func (f *fetcher) checkConn(conn net.Conn, vetted []netip.Addr) error {
	ra := conn.RemoteAddr()
	if ra == nil {
		return fmt.Errorf("%w: connection has no remote address", ErrForbiddenAddress)
	}
	ap, err := netip.ParseAddrPort(ra.String())
	if err != nil {
		return fmt.Errorf("%w: cannot parse remote address %q", ErrForbiddenAddress, ra.String())
	}
	remote := ap.Addr().Unmap().WithZone("")
	if forbidden(ap.Addr(), f.permitLoopback) {
		return forbiddenErr("connected to", ap.Addr())
	}
	for _, v := range vetted {
		if v.Unmap().WithZone("") == remote {
			return nil
		}
	}
	return fmt.Errorf("%w: connected to %s, which DNS did not return", ErrForbiddenAddress, remote)
}

// fetch GETs url and returns its body if the response is a 200 with a JSON
// content type and at most MaxDocumentBytes of body. Errors wrap ErrFetch.
func (f *fetcher) fetch(ctx context.Context, url string) (*fetched, error) {
	ctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetch, err)
	}
	req.Header.Set("User-Agent", f.userAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetch, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		detail := ""
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			detail = " (redirects are not followed)"
		}
		return nil, fmt.Errorf("%w: status %d%s", ErrFetch, resp.StatusCode, detail)
	}
	if !isJSONContentType(resp.Header.Get("Content-Type")) {
		return nil, fmt.Errorf("%w: content type %q is not JSON", ErrFetch, resp.Header.Get("Content-Type"))
	}
	if resp.ContentLength > MaxDocumentBytes {
		return nil, fmt.Errorf("%w: document is %d bytes, more than %d", ErrFetch, resp.ContentLength, MaxDocumentBytes)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxDocumentBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: reading body: %w", ErrFetch, err)
	}
	if len(body) > MaxDocumentBytes {
		return nil, fmt.Errorf("%w: document is more than %d bytes", ErrFetch, MaxDocumentBytes)
	}
	// A body that ended only after the deadline is not trusted as complete.
	// Cancelling the request closes the TLS connection with a close_notify,
	// and a server that reacts to it by ending its response can get a cleanly
	// terminated -- but cut short -- body to the reader before the socket
	// closes. It was always going to be a timeout; report it as one.
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: reading body: %w", ErrFetch, err)
	}
	return &fetched{body: body, cacheControl: strings.Join(resp.Header.Values("Cache-Control"), ",")}, nil
}

// isJSONContentType accepts application/json and any application/*+json, with
// any parameters (charset=utf-8 and the like).
func isJSONContentType(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return mt == "application/json" || (strings.HasPrefix(mt, "application/") && strings.HasSuffix(mt, "+json"))
}
