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

// getClientIP extracts the client IP address from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (set by proxies/load balancers)
	// Take the first IP if there are multiple (comma-separated)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		for i, char := range xff {
			if char == ',' {
				return xff[:i]
			}
		}
		return xff
	}
	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Fall back to RemoteAddr
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
