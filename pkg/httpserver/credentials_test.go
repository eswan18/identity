package httpserver

import (
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/eswan18/identity/pkg/db"
	"github.com/google/uuid"
)

func TestParseClientCredentials_BasicAuth(t *testing.T) {
	req, _ := http.NewRequest("POST", "/oauth/token", nil)
	req.SetBasicAuth("my-client-id", "my-client-secret")

	clientID, clientSecret := parseClientCredentials(req)
	if clientID != "my-client-id" {
		t.Errorf("expected client_id %q, got %q", "my-client-id", clientID)
	}
	if clientSecret != "my-client-secret" {
		t.Errorf("expected client_secret %q, got %q", "my-client-secret", clientSecret)
	}
}

func TestParseClientCredentials_FormValues(t *testing.T) {
	form := url.Values{
		"client_id":     {"form-client-id"},
		"client_secret": {"form-client-secret"},
	}
	req, _ := http.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	clientID, clientSecret := parseClientCredentials(req)
	if clientID != "form-client-id" {
		t.Errorf("expected client_id %q, got %q", "form-client-id", clientID)
	}
	if clientSecret != "form-client-secret" {
		t.Errorf("expected client_secret %q, got %q", "form-client-secret", clientSecret)
	}
}

func TestParseClientCredentials_BasicAuthTakesPrecedence(t *testing.T) {
	form := url.Values{
		"client_id":     {"form-client-id"},
		"client_secret": {"form-client-secret"},
	}
	req, _ := http.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("basic-client-id", "basic-client-secret")

	clientID, clientSecret := parseClientCredentials(req)
	if clientID != "basic-client-id" {
		t.Errorf("expected Basic auth client_id %q, got %q", "basic-client-id", clientID)
	}
	if clientSecret != "basic-client-secret" {
		t.Errorf("expected Basic auth client_secret %q, got %q", "basic-client-secret", clientSecret)
	}
}

func TestGenerateRandomString(t *testing.T) {
	// Test that it produces a string of expected length
	// 32 bytes = 44 base64 characters (with padding)
	str, err := generateRandomString(32)
	if err != nil {
		t.Fatalf("generateRandomString failed: %v", err)
	}

	// Base64 encoding: 32 bytes -> ceil(32/3)*4 = 44 characters
	expectedLen := 44
	if len(str) != expectedLen {
		t.Errorf("expected length %d, got %d", expectedLen, len(str))
	}
}

func TestGenerateRandomStringUniqueness(t *testing.T) {
	// Generate multiple strings and ensure they're all different
	seen := make(map[string]bool)
	iterations := 100

	for range iterations {
		str, err := generateRandomString(32)
		if err != nil {
			t.Fatalf("generateRandomString failed: %v", err)
		}

		if seen[str] {
			t.Errorf("generateRandomString produced duplicate: %s", str)
		}
		seen[str] = true
	}
}

func TestGenerateRandomStringDifferentLengths(t *testing.T) {
	tests := []struct {
		byteLen        int
		expectedB64Len int
	}{
		{16, 24}, // 16 bytes -> 24 base64 chars
		{32, 44}, // 32 bytes -> 44 base64 chars
		{64, 88}, // 64 bytes -> 88 base64 chars
	}

	for _, tt := range tests {
		str, err := generateRandomString(tt.byteLen)
		if err != nil {
			t.Fatalf("generateRandomString(%d) failed: %v", tt.byteLen, err)
		}
		if len(str) != tt.expectedB64Len {
			t.Errorf("generateRandomString(%d): expected %d chars, got %d", tt.byteLen, tt.expectedB64Len, len(str))
		}
	}
}

// TestRequireConfidentialClient_RejectsPublicClient covers the core of Issue 1: introspection
// and revocation (via authenticateConfidentialClient) must reject a caller that only proved
// it knows a public client's client_id, with no secret. This exercises the pure decision
// logic behind authenticateConfidentialClient without needing a database, since
// authenticateClient itself requires a live DB lookup.
func TestRequireConfidentialClient_RejectsPublicClient(t *testing.T) {
	publicClient := db.OauthClient{
		ID:             uuid.New(),
		ClientID:       "public-client",
		IsConfidential: false,
	}

	client, err := requireConfidentialClient(publicClient, nil)
	if err == nil {
		t.Fatal("expected an error for a public client, got nil")
	}
	if !errors.Is(err, ErrConfidentialClientRequired) {
		t.Errorf("expected ErrConfidentialClientRequired, got %v", err)
	}
	if !reflect.DeepEqual(client, db.OauthClient{}) {
		t.Errorf("expected zero-value client on rejection, got %+v", client)
	}
}

// TestRequireConfidentialClient_AllowsConfidentialClient ensures a client that authenticated
// as confidential (i.e. authenticateClient already verified its secret) passes through
// unchanged.
func TestRequireConfidentialClient_AllowsConfidentialClient(t *testing.T) {
	confidentialClient := db.OauthClient{
		ID:             uuid.New(),
		ClientID:       "confidential-client",
		ClientSecret:   sql.NullString{String: "shh", Valid: true},
		IsConfidential: true,
	}

	client, err := requireConfidentialClient(confidentialClient, nil)
	if err != nil {
		t.Fatalf("expected no error for a confidential client, got %v", err)
	}
	if !reflect.DeepEqual(client, confidentialClient) {
		t.Errorf("expected client to be returned unchanged, got %+v", client)
	}
}

// TestRequireConfidentialClient_PropagatesUpstreamError ensures that an authentication
// failure from authenticateClient (e.g. unknown client_id, or wrong secret for a confidential
// client) is passed through as-is rather than being masked.
func TestRequireConfidentialClient_PropagatesUpstreamError(t *testing.T) {
	upstreamErr := errors.New("invalid client credentials")

	client, err := requireConfidentialClient(db.OauthClient{}, upstreamErr)
	if !errors.Is(err, upstreamErr) {
		t.Errorf("expected upstream error to propagate, got %v", err)
	}
	if !reflect.DeepEqual(client, db.OauthClient{}) {
		t.Errorf("expected zero-value client on error, got %+v", client)
	}
}
