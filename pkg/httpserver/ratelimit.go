package httpserver

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// rateLimiterEntry represents a rate limiter for a single IP address
type rateLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// rateLimitStore manages rate limiters keyed by an arbitrary string. The key is
// an IP address for the global middleware and a user ID for the per-account
// verification-mail budget (see Server.allowVerificationMail); the store itself
// does not care which.
type rateLimitStore struct {
	limiters map[string]*rateLimiterEntry
	mu       sync.RWMutex
	cleanup  *time.Ticker

	// entryTTL is how long an unused entry is kept before the cleanup goroutine
	// discards it. It must be at least as long as the limiter takes to refill
	// from empty, or eviction hands back a fresh budget early and silently
	// weakens the limit: a 3-per-hour rule whose entries are dropped after ten
	// idle minutes is really a 3-per-ten-minutes rule for anyone willing to
	// pause. Callers pick a TTL that matches the budget they configure.
	entryTTL time.Duration
}

// Stop stops the cleanup ticker
func (r *rateLimitStore) Stop() {
	if r.cleanup != nil {
		r.cleanup.Stop()
	}
}

// Reset clears all rate limiters (useful for testing)
func (r *rateLimitStore) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.limiters = make(map[string]*rateLimiterEntry)
}

// newRateLimitStore creates a new rate limit store with automatic cleanup.
// entryTTL must be at least the limiter's refill time -- see the field comment.
func newRateLimitStore(entryTTL time.Duration) *rateLimitStore {
	store := &rateLimitStore{
		limiters: make(map[string]*rateLimiterEntry),
		cleanup:  time.NewTicker(5 * time.Minute),
		entryTTL: entryTTL,
	}

	// Start cleanup goroutine to remove old entries
	go store.cleanupOldEntries()

	return store
}

// cleanupOldEntries removes rate limiter entries unused for longer than entryTTL.
func (r *rateLimitStore) cleanupOldEntries() {
	for range r.cleanup.C {
		r.mu.Lock()
		now := time.Now()
		for key, entry := range r.limiters {
			if now.Sub(entry.lastSeen) > r.entryTTL {
				delete(r.limiters, key)
			}
		}
		r.mu.Unlock()
	}
}

// forget discards the entry for key, restoring its full budget.
//
// Used to clear an account's failed-attempt count once it authenticates
// successfully, which is the conventional semantics for a failure counter: the
// budget bounds consecutive failures, not lifetime use.
func (r *rateLimitStore) forget(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.limiters, key)
}

// getLimiter returns or creates the rate limiter for key, with the given
// sustained rate and burst. limit and burst are only consulted when the entry is
// first created; an existing entry keeps the budget it was created with.
func (r *rateLimitStore) getLimiter(key string, limit rate.Limit, burst int) *rate.Limiter {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, exists := r.limiters[key]
	if !exists {
		entry = &rateLimiterEntry{
			limiter:  rate.NewLimiter(limit, burst),
			lastSeen: time.Now(),
		}
		r.limiters[key] = entry
	} else {
		entry.lastSeen = time.Now()
	}

	return entry.limiter
}

// perMinute converts a requests-per-minute budget into a rate.Limit, e.g. 5
// requests per minute becomes one every 12 seconds.
func perMinute(requestsPerMinute int) rate.Limit {
	return rate.Every(time.Minute / time.Duration(requestsPerMinute))
}

// rateEvery expresses a budget as one unit per interval.
func rateEvery(interval time.Duration) rate.Limit {
	return rate.Every(interval)
}

// getClientIP extracts the client IP address from the request.
//
// SECURITY: The only header this trusts is CF-Connecting-IP, and only
// because of how this service is deployed: the k8s Service is ClusterIP
// (not directly reachable from the internet) and production traffic arrives
// exclusively via a Cloudflare Tunnel (see k8s/README.md). Cloudflare sets
// CF-Connecting-IP to the real client IP and OVERWRITES any value the
// client supplies, so an external attacker cannot forge it as long as the
// origin is reachable only through Cloudflare. If that assumption ever
// changes - e.g. the service is exposed via a LoadBalancer/NodePort, a
// non-Cloudflare ingress, or any other path that bypasses the tunnel - this
// header becomes client-controlled and MUST stop being trusted here.
//
// X-Forwarded-For and X-Real-IP are deliberately NOT trusted: on any direct
// connection they are fully client-controlled, and trusting them lets an
// attacker mint a fresh rate-limit bucket per request by sending a
// different fabricated value each time, defeating the limiter entirely.
// (For the same reason, chi's middleware.RealIP is not installed in
// server.go.)
//
// When CF-Connecting-IP is absent or not a valid IP (local dev, staging via
// the Tailscale ingress, in-cluster requests), we fall back to the host
// portion of r.RemoteAddr - the actual TCP peer address, which cannot be
// spoofed.
func getClientIP(r *http.Request) string {
	if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
		if parsed := net.ParseIP(cfIP); parsed != nil {
			return parsed.String()
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// rateLimitMiddleware creates a middleware that enforces rate limiting.
//
// Requests under staticPathPrefix (see routes.go, which mounts the static
// file server on that same constant) are exempt: a single page load pulls
// the HTML plus several static assets (CSS, JS, images), so applying the
// same per-IP budget meant to limit abuse of auth/API endpoints to static
// assets too caused ordinary navigation to burn through the whole budget
// and start getting 429'd. Static asset serving doesn't need per-IP abuse
// protection the way endpoints like login/token do, so it simply bypasses
// the limiter rather than consuming a request from it.
func rateLimitMiddleware(store *rateLimitStore, requestsPerMinute int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, staticPathPrefix) {
				next.ServeHTTP(w, r)
				return
			}

			ip := getClientIP(r)
			limiter := store.getLimiter(ip, perMinute(requestsPerMinute), requestsPerMinute)

			if !limiter.Allow() {
				http.Error(w, "Rate limit exceeded. Please try again later.", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
