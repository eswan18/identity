package cimd

import (
	"context"
	"crypto/x509"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	// MinCacheTTL is the shortest time a valid document is cached, whatever
	// its Cache-Control says (no-store and no-cache included).
	MinCacheTTL = 5 * time.Minute
	// MaxCacheTTL is the longest.
	MaxCacheTTL = 24 * time.Hour
	// maxCacheEntries bounds memory. The allow-list already bounds which
	// documents can be valid; this is a backstop.
	maxCacheEntries = 1000
)

// Config configures a Resolver.
type Config struct {
	// AllowedHosts are the client_id hosts whose documents identity will
	// fetch (CIMD_ALLOWED_HOSTS; initially "claude.ai"). Each must be a
	// lowercase DNS name with no scheme, port or path; matching is exact, so
	// "claude.ai" does not admit "www.claude.ai". Empty disables CIMD: every
	// Resolve fails with ErrHostNotAllowed.
	AllowedHosts []string
	// UserAgent is sent on every fetch. Empty means DefaultUserAgent.
	UserAgent string
}

// testHooks are the seams package tests use to run without the network. They
// are unexported so production code outside this package cannot reach them;
// NewResolver always passes the zero value.
type testHooks struct {
	lookup         lookupFunc
	dial           dialFunc
	now            func() time.Time
	permitLoopback bool           // let 127.0.0.0/8 and ::1 through the SSRF guard
	rootCAs        *x509.CertPool // trust an httptest server's certificate
	timeout        time.Duration  // replaces FetchTimeout when non-zero
}

// Resolver fetches, validates and caches Client ID Metadata Documents. It is
// safe for concurrent use.
type Resolver struct {
	allowed map[string]bool
	fetcher *fetcher
	now     func() time.Time

	mu    sync.Mutex
	cache map[string]*Metadata
	group singleflight.Group
}

// NewResolver returns a Resolver, or an error if an allow-list entry is not a
// lowercase DNS name.
func NewResolver(cfg Config) (*Resolver, error) {
	return newResolver(cfg, testHooks{})
}

func newResolver(cfg Config, h testHooks) (*Resolver, error) {
	allowed := make(map[string]bool, len(cfg.AllowedHosts))
	for _, host := range cfg.AllowedHosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		if !validHostName(host) {
			return nil, fmt.Errorf("cimd: allowed host %q must be a lowercase DNS name with no scheme, port or path", host)
		}
		allowed[host] = true
	}
	ua := cfg.UserAgent
	if ua == "" {
		ua = DefaultUserAgent
	}
	now := h.now
	if now == nil {
		now = time.Now
	}
	return &Resolver{
		allowed: allowed,
		fetcher: newFetcher(ua, h),
		now:     now,
		cache:   make(map[string]*Metadata),
	}, nil
}

// Enabled reports whether any host is allowed, i.e. whether identity should
// advertise client_id_metadata_document_supported.
func (r *Resolver) Enabled() bool { return len(r.allowed) > 0 }

// HostAllowed reports whether clientID is a valid Client Identifier URL on an
// allowed host. It never touches the network.
func (r *Resolver) HostAllowed(clientID string) bool {
	return r.checkClientID(clientID) == nil
}

func (r *Resolver) checkClientID(clientID string) error {
	if err := ValidateClientIDURL(clientID); err != nil {
		return err
	}
	if host := hostOf(clientID); !r.allowed[host] {
		return fmt.Errorf("%w: %s", ErrHostNotAllowed, host)
	}
	return nil
}

// Resolve returns the validated metadata for clientID, from the cache when it
// is fresh and otherwise by fetching it. The error wraps exactly one of
// ErrNotClientIDURL, ErrHostNotAllowed, ErrFetch or ErrInvalidDocument; the
// first two are decided without any network activity.
//
// A fetch shared by concurrent callers runs to completion (bounded by
// FetchTimeout) even if the caller that started it gives up, so one
// cancelled request cannot fail the others; each caller still returns as soon
// as its own ctx is done.
func (r *Resolver) Resolve(ctx context.Context, clientID string) (*Metadata, error) {
	if err := r.checkClientID(clientID); err != nil {
		return nil, err
	}
	if md := r.cached(clientID); md != nil {
		return md, nil
	}
	ch := r.group.DoChan(clientID, func() (any, error) {
		// A caller that waited behind an earlier flight may find its result
		// already cached.
		if md := r.cached(clientID); md != nil {
			return md, nil
		}
		return r.fetchAndStore(context.WithoutCancel(ctx), clientID)
	})
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: %w", ErrFetch, ctx.Err())
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		return res.Val.(*Metadata).clone(), nil
	}
}

// cached returns a copy of a fresh cache entry, or nil.
func (r *Resolver) cached(clientID string) *Metadata {
	r.mu.Lock()
	defer r.mu.Unlock()
	md, ok := r.cache[clientID]
	if !ok {
		return nil
	}
	if !r.now().Before(md.ExpiresAt) {
		delete(r.cache, clientID)
		return nil
	}
	return md.clone()
}

func (r *Resolver) fetchAndStore(ctx context.Context, clientID string) (*Metadata, error) {
	got, err := r.fetcher.fetch(ctx, clientID)
	if err != nil {
		return nil, err
	}
	md, err := parseDocument(clientID, got.body)
	if err != nil {
		return nil, err
	}
	// Truncated to Postgres precision (and stripped of the monotonic reading),
	// so the value survives a round trip through metadata_fetched_at intact.
	md.FetchedAt = r.now().Truncate(time.Microsecond)
	md.ExpiresAt = md.FetchedAt.Add(cacheTTL(got.cacheControl))

	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.cache) >= maxCacheEntries {
		now := r.now()
		for k, v := range r.cache {
			if !now.Before(v.ExpiresAt) {
				delete(r.cache, k)
			}
		}
		for k := range r.cache {
			if len(r.cache) < maxCacheEntries {
				break
			}
			delete(r.cache, k)
		}
	}
	r.cache[clientID] = md
	return md.clone(), nil
}

// cacheTTL turns a Cache-Control header into how long to keep a document.
//
// CIMD §5.2 says to respect HTTP cache headers but lets the authorization
// server set its own bounds; identity's are [MinCacheTTL, MaxCacheTTL].
// max-age is clamped into them. With no max-age -- including no-store,
// no-cache, a malformed value, or no header at all -- the document is kept
// for MinCacheTTL: identity is not a shared HTTP cache, it holds a parsed
// client registration, and a floor keeps a burst of authorizations from
// becoming a burst of fetches. The floor is also the longest a changed
// document can go unnoticed. Expires and s-maxage are ignored.
func cacheTTL(header string) time.Duration {
	ttl := MinCacheTTL
	for _, directive := range strings.Split(header, ",") {
		name, value, _ := strings.Cut(strings.TrimSpace(directive), "=")
		if !strings.EqualFold(strings.TrimSpace(name), "max-age") {
			continue
		}
		secs, err := strconv.ParseInt(strings.Trim(strings.TrimSpace(value), `"`), 10, 64)
		if err != nil || secs < 0 {
			return MinCacheTTL
		}
		if secs > int64(MaxCacheTTL/time.Second) {
			return MaxCacheTTL
		}
		ttl = time.Duration(secs) * time.Second
		break
	}
	return min(max(ttl, MinCacheTTL), MaxCacheTTL)
}
