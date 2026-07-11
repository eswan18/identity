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
