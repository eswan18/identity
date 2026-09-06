package httpserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestWriteTokenErrorStatus pins which token-endpoint errors are answered with
// a 5xx rather than RFC 6749 §5.2's 400.
//
// The distinction is not cosmetic. Every error here used to be a 400, including
// server_error — which handleRefreshTokenGrant returns when the database fails
// while verifying the user, revoking the old token, or minting the new one. A
// client reading only the status saw "your request was bad" and concluded the
// grant was dead, so a Neon blip signed people out of healthy sessions. Three
// clients had to learn to parse the body to avoid it.
func TestWriteTokenErrorStatus(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		// Ours: the request was fine, we failed to serve it.
		{"database failed mid-refresh", "server_error", http.StatusServiceUnavailable},
		{"briefly unavailable", "temporarily_unavailable", http.StatusServiceUnavailable},

		// Theirs: something about the request or the grant is wrong, and
		// repeating it unchanged will not help.
		{"token revoked, expired or replayed", "invalid_grant", http.StatusBadRequest},
		{"refresh token carries admin scopes", "invalid_scope", http.StatusBadRequest},
		{"malformed request", "invalid_request", http.StatusBadRequest},
		{"client may not use this grant", "unauthorized_client", http.StatusBadRequest},
		{"unknown grant type", "unsupported_grant_type", http.StatusBadRequest},
	}

	s := &Server{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			s.writeTokenError(rec, tt.code, "a description")

			if rec.Code != tt.want {
				t.Errorf("status = %d, want %d", rec.Code, tt.want)
			}

			// The body is the contract every client that DOES parse relies on.
			// Changing the status must not disturb it.
			var body map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("body is not JSON: %v", err)
			}
			if body["error"] != tt.code {
				t.Errorf("error = %q, want %q", body["error"], tt.code)
			}
			if body["error_description"] != "a description" {
				t.Errorf("error_description = %q, want %q", body["error_description"], "a description")
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}
		})
	}
}

// TestWriteInvalidClientErrorStatusUnchanged guards the one token-endpoint error
// that was never a 400. RFC 6749 §5.2 requires 401 with a WWW-Authenticate
// header for a failed client authentication, and it goes through its own writer
// — so the change above must not have reached it.
func TestWriteInvalidClientErrorStatusUnchanged(t *testing.T) {
	rec := httptest.NewRecorder()
	(&Server{}).writeInvalidClientError(rec)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != `Basic realm="oauth"` {
		t.Errorf("WWW-Authenticate = %q, want %q", got, `Basic realm="oauth"`)
	}
}
