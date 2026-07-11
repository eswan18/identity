package httpserver

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// TestWriteTokenError_Uses400 verifies that every token-endpoint error other than
// invalid_client is reported as HTTP 400, per RFC 6749 §5.2's default error status.
func TestWriteTokenError_Uses400(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()

	s.writeTokenError(rec, "invalid_grant", "Refresh token has already been used")

	if rec.Code != 400 {
		t.Errorf("expected status 400, got %d", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != "" {
		t.Errorf("expected no WWW-Authenticate header for invalid_grant, got %q", got)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to unmarshal response body: %v", err)
	}
	if body["error"] != "invalid_grant" {
		t.Errorf("expected error code invalid_grant, got %q", body["error"])
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
