package httpserver

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestRedactedRequestPath_RedactsToken is a regression test for secrets leaking into
// access logs: password-reset and email-verification links pass their single-use
// secret token as a "token" query parameter (see password_reset.go,
// email_verification.go). The raw request logger must never write that value out.
func TestRedactedRequestPath_RedactsToken(t *testing.T) {
	const secretToken = "super-secret-single-use-token"

	tests := []struct {
		name    string
		rawURL  string
		wantHas string // substring that must be present (redacted form)
		wantNot string // substring that must NOT be present (the secret itself)
	}{
		{
			name:    "reset-password token is redacted",
			rawURL:  "/oauth/reset-password?token=" + secretToken,
			wantHas: "token=REDACTED",
			wantNot: secretToken,
		},
		{
			name:    "verify-email token is redacted",
			rawURL:  "/oauth/verify-email?token=" + secretToken,
			wantHas: "token=REDACTED",
			wantNot: secretToken,
		},
		{
			name:    "token redacted alongside other params, which are preserved",
			rawURL:  "/oauth/reset-password?foo=bar&token=" + secretToken,
			wantHas: "foo=bar",
			wantNot: secretToken,
		},
		{
			name:    "no token param is left untouched",
			rawURL:  "/oauth/login?client_id=abc&state=xyz",
			wantHas: "client_id=abc",
			wantNot: "REDACTED",
		},
		{
			name:    "no query string at all",
			rawURL:  "/health",
			wantHas: "/health",
			wantNot: "?",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.rawURL)
			if err != nil {
				t.Fatalf("url.Parse: %v", err)
			}
			got := redactedRequestPath(u)
			if tt.wantHas != "" && !strings.Contains(got, tt.wantHas) {
				t.Errorf("redactedRequestPath(%q) = %q, want it to contain %q", tt.rawURL, got, tt.wantHas)
			}
			if strings.Contains(got, tt.wantNot) {
				t.Errorf("redactedRequestPath(%q) = %q, must not contain %q", tt.rawURL, got, tt.wantNot)
			}
		})
	}
}

// TestRequestLoggingMiddleware_DoesNotLogToken drives an actual request through the
// middleware and asserts the secret token never appears in the emitted log line, while
// the operationally useful fields (method, path, status) still do.
func TestRequestLoggingMiddleware_DoesNotLogToken(t *testing.T) {
	const secretToken = "super-secret-single-use-token"

	var buf bytes.Buffer
	oldFlags := log.Flags()
	oldOutput := log.Writer()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(oldOutput)
		log.SetFlags(oldFlags)
	})

	handler := requestLoggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/oauth/reset-password?token="+secretToken, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	logged := buf.String()
	if strings.Contains(logged, secretToken) {
		t.Fatalf("request log leaked the secret token: %q", logged)
	}
	if !strings.Contains(logged, "GET") || !strings.Contains(logged, "/oauth/reset-password") {
		t.Errorf("request log is missing useful fields (method/path): %q", logged)
	}
	if !strings.Contains(logged, "200") {
		t.Errorf("request log is missing the status code: %q", logged)
	}
}
