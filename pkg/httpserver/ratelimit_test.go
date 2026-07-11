package httpserver

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestGetClientIP_IgnoresSpoofableHeaders verifies that getClientIP keys
// exclusively on the real transport peer address (RemoteAddr) and does not
// trust client-supplied X-Forwarded-For / X-Real-IP headers. If it did trust
// them, an attacker could send a different fabricated value on every request
// and get a brand new rate-limit bucket each time, defeating rate limiting.
func TestGetClientIP_IgnoresSpoofableHeaders(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		want       string
	}{
		{
			name:       "no headers, uses RemoteAddr host",
			remoteAddr: "203.0.113.10:54321",
			want:       "203.0.113.10",
		},
		{
			name:       "spoofed X-Forwarded-For is ignored",
			remoteAddr: "203.0.113.10:54321",
			headers:    map[string]string{"X-Forwarded-For": "1.2.3.4"},
			want:       "203.0.113.10",
		},
		{
			name:       "spoofed X-Forwarded-For with multiple values is ignored",
			remoteAddr: "203.0.113.10:54321",
			headers:    map[string]string{"X-Forwarded-For": "9.9.9.9, 8.8.8.8"},
			want:       "203.0.113.10",
		},
		{
			name:       "spoofed X-Real-IP is ignored",
			remoteAddr: "203.0.113.10:54321",
			headers:    map[string]string{"X-Real-IP": "6.6.6.6"},
			want:       "203.0.113.10",
		},
		{
			name:       "RemoteAddr without a port is returned as-is",
			remoteAddr: "203.0.113.10",
			want:       "203.0.113.10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			got := getClientIP(req)
			if got != tt.want {
				t.Errorf("getClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestRateLimitMiddleware_SpoofedHeadersShareLimiter verifies the end-to-end
// behavior of rateLimitMiddleware: two requests from the same transport peer
// (same RemoteAddr) but with different, attacker-controlled X-Forwarded-For
// values must share the same rate limiter bucket rather than each getting a
// fresh one. This is the regression test for the IP-spoofing rate-limit
// bypass.
func TestRateLimitMiddleware_SpoofedHeadersShareLimiter(t *testing.T) {
	store := newRateLimitStore()
	defer store.Stop()

	// Only allow 1 request per minute so the second request from the same
	// peer is guaranteed to be blocked if (and only if) spoofed headers are
	// correctly ignored.
	handler := rateLimitMiddleware(store, 1)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	makeRequest := func(spoofedXFF string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "203.0.113.10:11111"
		req.Header.Set("X-Forwarded-For", spoofedXFF)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	first := makeRequest("1.1.1.1")
	if first.Code != http.StatusOK {
		t.Fatalf("first request: got status %d, want %d", first.Code, http.StatusOK)
	}

	// Same RemoteAddr, but a completely different spoofed X-Forwarded-For.
	// Prior to the fix, this would have been treated as a brand new client
	// and allowed through with a fresh limiter.
	second := makeRequest("9.9.9.9")
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second request (spoofed XFF, same RemoteAddr): got status %d, want %d (rate limit should apply)", second.Code, http.StatusTooManyRequests)
	}

	// Sanity check: only one limiter bucket should have been created, keyed
	// on RemoteAddr rather than the spoofed header.
	store.mu.RLock()
	numLimiters := len(store.limiters)
	store.mu.RUnlock()
	if numLimiters != 1 {
		t.Errorf("expected exactly 1 rate limiter bucket, got %d", numLimiters)
	}
}
