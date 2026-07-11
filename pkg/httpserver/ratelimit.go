package httpserver

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// rateLimiterEntry represents a rate limiter for a single IP address
type rateLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// rateLimitStore manages rate limiters per IP address
type rateLimitStore struct {
	limiters map[string]*rateLimiterEntry
	mu       sync.RWMutex
	cleanup  *time.Ticker
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

// newRateLimitStore creates a new rate limit store with automatic cleanup
func newRateLimitStore() *rateLimitStore {
	store := &rateLimitStore{
		limiters: make(map[string]*rateLimiterEntry),
		cleanup:  time.NewTicker(5 * time.Minute),
	}

	// Start cleanup goroutine to remove old entries
	go store.cleanupOldEntries()

	return store
}

// cleanupOldEntries removes rate limiter entries that haven't been used in 10 minutes
func (r *rateLimitStore) cleanupOldEntries() {
	for range r.cleanup.C {
		r.mu.Lock()
		now := time.Now()
		for ip, entry := range r.limiters {
			if now.Sub(entry.lastSeen) > 10*time.Minute {
				delete(r.limiters, ip)
			}
		}
		r.mu.Unlock()
	}
}

// getLimiter returns or creates a rate limiter for the given IP address
func (r *rateLimitStore) getLimiter(ip string, requestsPerMinute int) *rate.Limiter {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, exists := r.limiters[ip]
	if !exists {
		// Create new limiter: rate.Every calculates the interval between requests
		// For 5 requests per minute: rate.Every(12 seconds) = 5 requests/minute
		interval := time.Minute / time.Duration(requestsPerMinute)
		limiter := rate.NewLimiter(rate.Every(interval), requestsPerMinute)
		entry = &rateLimiterEntry{
			limiter:  limiter,
			lastSeen: time.Now(),
		}
		r.limiters[ip] = entry
	} else {
		entry.lastSeen = time.Now()
	}

	return entry.limiter
}

// getClientIP extracts the client IP address from the request.
//
// SECURITY: This intentionally ignores client-supplied headers such as
// X-Forwarded-For and X-Real-IP. Those headers are fully controlled by the
// client and, if trusted, let an attacker get a fresh rate-limit bucket on
// every request simply by sending a different (fabricated) value each time
// - defeating the rate limiter entirely. Instead we key on r.RemoteAddr,
// which is the actual TCP peer address and cannot be spoofed by the client.
//
// Tradeoff: if this service sits behind a reverse proxy/load balancer that
// doesn't preserve the original client IP, RemoteAddr will be the proxy's
// address and all proxied traffic will share a single rate-limit bucket.
// That's an availability/precision tradeoff, not a security one - it's
// strictly safer than trusting spoofable headers. If a trusted proxy is
// introduced in front of this service, this function (and the removed
// middleware.RealIP in server.go) should be revisited to derive the real
// client IP from a header that the trusted proxy guarantees to set/sanitize.
func getClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// rateLimitMiddleware creates a middleware that enforces rate limiting
func rateLimitMiddleware(store *rateLimitStore, requestsPerMinute int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := getClientIP(r)
			limiter := store.getLimiter(ip, requestsPerMinute)

			if !limiter.Allow() {
				http.Error(w, "Rate limit exceeded. Please try again later.", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
