package httpserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestWriteTokenErrorStatus pins which token-endpoint errors are answered with
// a 5xx rather than RFC 6749 §5.2's default 400.
//
// The distinction is not cosmetic. Every error here used to be a 400, including
// server_error — which handleRefreshTokenGrant returns when the database fails
// while verifying the user, revoking the old token, or minting the new one. A
// client reading only the status saw "your request was bad" and concluded the
// grant was dead, so a database blip signed people out of healthy sessions.
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			(&Server{}).writeTokenError(rec, tt.code, "a description")

			if rec.Code != tt.want {
				t.Errorf("status = %d, want %d", rec.Code, tt.want)
			}
			if got := rec.Header().Get("WWW-Authenticate"); got != "" {
				t.Errorf("expected no WWW-Authenticate header, got %q", got)
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
		})
	}
}

// TestWriteInvalidClientError_Uses401 verifies that a failed client authentication
// attempt at the token endpoint (invalid_client) is reported as HTTP 401 with a
// WWW-Authenticate challenge, matching RFC 6749 §5.2 and the behavior already used
// by the introspection and revocation endpoints for the same error code.
func TestWriteInvalidClientError_Uses401(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()

	s.writeInvalidClientError(rec)

	if rec.Code != 401 {
		t.Errorf("expected status 401, got %d", rec.Code)
	}
	wantAuth := `Basic realm="oauth"`
	if got := rec.Header().Get("WWW-Authenticate"); got != wantAuth {
		t.Errorf("expected WWW-Authenticate %q, got %q", wantAuth, got)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to unmarshal response body: %v", err)
	}
	if body["error"] != "invalid_client" {
		t.Errorf("expected error code invalid_client, got %q", body["error"])
	}
}
