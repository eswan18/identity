package httpserver

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestGenerateVerificationToken(t *testing.T) {
	rawToken1, hash1, err := generateVerificationToken()
	if err != nil {
		t.Fatalf("generateVerificationToken failed: %v", err)
	}

	// Token should be non-empty
	if rawToken1 == "" {
		t.Error("rawToken should not be empty")
	}
	if hash1 == "" {
		t.Error("hash should not be empty")
	}

	// Token should be 64 hex characters (32 bytes)
	if len(rawToken1) != 64 {
		t.Errorf("expected rawToken length 64, got %d", len(rawToken1))
	}

	// Hash should be 64 hex characters (SHA-256 = 32 bytes)
	if len(hash1) != 64 {
		t.Errorf("expected hash length 64, got %d", len(hash1))
	}

	// Hash should match SHA-256 of raw token
	expectedHash := sha256.Sum256([]byte(rawToken1))
	expectedHashHex := hex.EncodeToString(expectedHash[:])
	if hash1 != expectedHashHex {
		t.Errorf("hash mismatch: expected %s, got %s", expectedHashHex, hash1)
	}

	// Each call should generate different tokens
	rawToken2, hash2, err := generateVerificationToken()
	if err != nil {
		t.Fatalf("second generateVerificationToken failed: %v", err)
	}
	if rawToken1 == rawToken2 {
		t.Error("tokens should be unique")
	}
	if hash1 == hash2 {
		t.Error("hashes should be unique")
	}
}

func TestHashToken(t *testing.T) {
	testCases := []struct {
		name     string
		token    string
		expected string
	}{
		{
			name:     "empty token",
			token:    "",
			expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "simple token",
			token:    "test",
			expected: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		},
		{
			name:     "hex token",
			token:    "abc123def456",
			expected: "e861b2eab679927cfa36fe256e9deb1969b0468ad0744d61064f9d188333aec6",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := hashToken(tc.token)
			if result != tc.expected {
				t.Errorf("hashToken(%q) = %q, expected %q", tc.token, result, tc.expected)
			}
		})
	}
}

func TestHashToken_Consistency(t *testing.T) {
	token := "my-verification-token-123"

	// Hash should be consistent across multiple calls
	hash1 := hashToken(token)
	hash2 := hashToken(token)
	hash3 := hashToken(token)

	if hash1 != hash2 || hash2 != hash3 {
		t.Error("hashToken should return consistent results")
	}
}

func TestBuildVerificationEmailHTML(t *testing.T) {
	username := "testuser"
	verifyURL := "https://example.com/verify?token=abc123"

	html := buildVerificationEmailHTML(username, verifyURL)

	// Should contain username
	if !contains(html, username) {
		t.Error("HTML should contain username")
	}

	// Should contain verify URL (twice - in button and plain text)
	if !contains(html, verifyURL) {
		t.Error("HTML should contain verification URL")
	}

	// Should be valid HTML structure
	if !contains(html, "<!DOCTYPE html>") {
		t.Error("HTML should have DOCTYPE")
	}
	if !contains(html, "<html>") {
		t.Error("HTML should have html tag")
	}
	if !contains(html, "Verify your email") {
		t.Error("HTML should have verification message")
	}
	if !contains(html, "24 hours") {
		t.Error("HTML should mention expiration time")
	}
}

func TestBuildVerificationEmailText(t *testing.T) {
	username := "testuser"
	verifyURL := "https://example.com/verify?token=abc123"

	text := buildVerificationEmailText(username, verifyURL)

	// Should contain username
	if !contains(text, username) {
		t.Error("Text should contain username")
	}

	// Should contain verify URL
	if !contains(text, verifyURL) {
		t.Error("Text should contain verification URL")
	}

	// Should mention expiration
	if !contains(text, "24 hours") {
		t.Error("Text should mention expiration time")
	}
}

// contains is a helper to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
