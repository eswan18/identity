package httpserver

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestGetClientIP verifies the trust model of getClientIP:
//   - CF-Connecting-IP is trusted when present and valid, because the origin
//     is only reachable through the Cloudflare Tunnel and Cloudflare
//     overwrites any client-supplied value.
//   - X-Forwarded-For and X-Real-IP are never trusted; they are fully
//     client-controlled. If they were trusted, an attacker could send a
//     different fabricated value on every request and get a brand new
//     rate-limit bucket each time, defeating rate limiting.
//   - Absent/invalid CF-Connecting-IP falls back to the RemoteAddr host.
func TestGetClientIP(t *testing.T) {
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
			name:       "valid CF-Connecting-IP is trusted",
			remoteAddr: "10.0.0.5:54321", // e.g. the cloudflared connector pod
			headers:    map[string]string{"CF-Connecting-IP": "198.51.100.7"},
			want:       "198.51.100.7",
		},
		{
			name:       "valid IPv6 CF-Connecting-IP is trusted",
			remoteAddr: "10.0.0.5:54321",
			headers:    map[string]string{"CF-Connecting-IP": "2001:db8::1"},
			want:       "2001:db8::1",
		},
		{
			name:       "invalid CF-Connecting-IP falls back to RemoteAddr",
			remoteAddr: "203.0.113.10:54321",
			headers:    map[string]string{"CF-Connecting-IP": "not-an-ip"},
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
			name:       "CF-Connecting-IP wins over spoofed XFF and X-Real-IP",
			remoteAddr: "10.0.0.5:54321",
			headers: map[string]string{
				"CF-Connecting-IP": "198.51.100.7",
				"X-Forwarded-For":  "1.2.3.4",
				"X-Real-IP":        "6.6.6.6",
			},
			want: "198.51.100.7",
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

// rateLimitTestHandler builds a rateLimitMiddleware-wrapped handler that
// allows only 1 request per minute, so a second request sharing the same
// limiter bucket is guaranteed to be rejected.
func rateLimitTestHandler(t *testing.T) (http.Handler, *rateLimitStore) {
	t.Helper()
	store := newRateLimitStore()
	t.Cleanup(store.Stop)
	handler := rateLimitMiddleware(store, 1)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	return handler, store
}

func doRateLimitedRequest(handler http.Handler, remoteAddr string, headers map[string]string) int {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remoteAddr
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Code
}

// TestRateLimitMiddleware_SpoofedXFFSharesLimiter is the regression test for
// the IP-spoofing rate-limit bypass: two requests from the same transport
// peer (same RemoteAddr) with different, attacker-controlled X-Forwarded-For
// values must share one limiter bucket rather than each getting a fresh one.
func TestRateLimitMiddleware_SpoofedXFFSharesLimiter(t *testing.T) {
	handler, store := rateLimitTestHandler(t)

	if code := doRateLimitedRequest(handler, "203.0.113.10:11111", map[string]string{"X-Forwarded-For": "1.1.1.1"}); code != http.StatusOK {
		t.Fatalf("first request: got status %d, want %d", code, http.StatusOK)
	}

	// Same RemoteAddr, completely different spoofed X-Forwarded-For. Prior
	// to the fix this was treated as a brand new client with a fresh bucket.
	if code := doRateLimitedRequest(handler, "203.0.113.10:11111", map[string]string{"X-Forwarded-For": "9.9.9.9"}); code != http.StatusTooManyRequests {
		t.Fatalf("second request (spoofed XFF, same RemoteAddr): got status %d, want %d", code, http.StatusTooManyRequests)
	}

	store.mu.RLock()
	numLimiters := len(store.limiters)
	store.mu.RUnlock()
	if numLimiters != 1 {
		t.Errorf("expected exactly 1 rate limiter bucket, got %d", numLimiters)
	}
}

// TestRateLimitMiddleware_CFConnectingIPIsTheKey verifies that behind the
// Cloudflare Tunnel (where all requests share the cloudflared connector's
// RemoteAddr) the limiter is keyed on CF-Connecting-IP: requests with the
// SAME CF-Connecting-IP share a bucket even across different RemoteAddrs,
// and requests with DIFFERENT CF-Connecting-IP values get separate buckets.
func TestRateLimitMiddleware_CFConnectingIPIsTheKey(t *testing.T) {
	handler, store := rateLimitTestHandler(t)

	// Same CF-Connecting-IP, different RemoteAddr (e.g. two cloudflared
	// replicas): must share one bucket, so the second request is limited.
	if code := doRateLimitedRequest(handler, "10.0.0.5:11111", map[string]string{"CF-Connecting-IP": "198.51.100.7"}); code != http.StatusOK {
		t.Fatalf("first request from client A: got status %d, want %d", code, http.StatusOK)
	}
	if code := doRateLimitedRequest(handler, "10.0.0.6:22222", map[string]string{"CF-Connecting-IP": "198.51.100.7"}); code != http.StatusTooManyRequests {
		t.Fatalf("second request from client A via different RemoteAddr: got status %d, want %d", code, http.StatusTooManyRequests)
	}

	// A different CF-Connecting-IP (a different real client), even from the
	// same RemoteAddr, must get its own bucket and NOT be throttled by
	// client A's traffic.
	if code := doRateLimitedRequest(handler, "10.0.0.5:11111", map[string]string{"CF-Connecting-IP": "198.51.100.8"}); code != http.StatusOK {
		t.Fatalf("first request from client B: got status %d, want %d", code, http.StatusOK)
	}

	store.mu.RLock()
	numLimiters := len(store.limiters)
	store.mu.RUnlock()
	if numLimiters != 2 {
		t.Errorf("expected exactly 2 rate limiter buckets (one per CF-Connecting-IP), got %d", numLimiters)
	}
}
