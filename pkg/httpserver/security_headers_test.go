package httpserver

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eswan18/identity/pkg/config"
)

// TestSecurityHeadersMiddleware_SetsBaselineHeaders verifies that every response gets
// the clickjacking/MIME-sniffing/referrer protections regardless of the secure-context
// signal, since these don't depend on TLS.
func TestSecurityHeadersMiddleware_SetsBaselineHeaders(t *testing.T) {
	handler := securityHeadersMiddleware(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/oauth/consent", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	tests := []struct {
		header string
		want   string
	}{
		{"X-Frame-Options", "DENY"},
		{"Content-Security-Policy", "frame-ancestors 'none'"},
		{"X-Content-Type-Options", "nosniff"},
		{"Referrer-Policy", "no-referrer"},
	}
	for _, tt := range tests {
		if got := rec.Header().Get(tt.header); got != tt.want {
			t.Errorf("header %s = %q, want %q", tt.header, got, tt.want)
		}
	}
}

// TestSecurityHeadersMiddleware_HSTSGatedOnSecureContext verifies that
// Strict-Transport-Security is only sent when the caller says the service is being
// served over HTTPS. Sending it unconditionally would be actively harmful in local
// HTTP development: browsers would refuse plain-HTTP connections to that host for the
// max-age duration.
func TestSecurityHeadersMiddleware_HSTSGatedOnSecureContext(t *testing.T) {
	newHandler := func(secure bool) http.Handler {
		return securityHeadersMiddleware(secure)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
	}

	t.Run("insecure context omits HSTS", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		newHandler(false).ServeHTTP(rec, req)

		if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
			t.Errorf("Strict-Transport-Security = %q, want empty when not in a secure context", got)
		}
	})

	t.Run("secure context sends HSTS", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		newHandler(true).ServeHTTP(rec, req)

		if got := rec.Header().Get("Strict-Transport-Security"); got == "" {
			t.Error("Strict-Transport-Security header missing when serving over HTTPS")
		}
	})
}

// TestIsSecureContext verifies the signal that gates both the session cookie's Secure
// attribute and HSTS: it must be derived from the service's public issuer URL, never
// from config.HTTPAddress (which is just the local listen address, e.g. ":8000", and
// so would always look "insecure" even in production behind TLS -- that was the bug).
func TestIsSecureContext(t *testing.T) {
	tests := []struct {
		name   string
		issuer string
		want   bool
	}{
		{"https issuer is secure", "https://identity.example.com", true},
		{"http issuer is not secure", "http://localhost:8000", false},
		{"issuer without scheme is not secure", "identity.example.com", false},
		{"empty issuer is not secure", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{JWTIssuer: tt.issuer}
			if got := isSecureContext(cfg); got != tt.want {
				t.Errorf("isSecureContext(issuer=%q) = %v, want %v", tt.issuer, got, tt.want)
			}
		})
	}
}
