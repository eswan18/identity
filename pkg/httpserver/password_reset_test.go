package httpserver

import (
	"encoding/base64"
	"testing"
)

func TestGenerateResetToken(t *testing.T) {
	rawToken1, hash1, err := generateResetToken()
	if err != nil {
		t.Fatalf("generateResetToken failed: %v", err)
	}

	// Token should be non-empty
	if rawToken1 == "" {
		t.Error("rawToken should not be empty")
	}
	if hash1 == "" {
		t.Error("hash should not be empty")
	}

	// Token should be base64 URL encoded (44 chars for 32 bytes)
	if len(rawToken1) != 44 {
		t.Errorf("expected rawToken length 44 (base64 of 32 bytes), got %d", len(rawToken1))
	}

	// Token should be valid base64 URL encoding
	decoded, err := base64.URLEncoding.DecodeString(rawToken1)
	if err != nil {
		t.Errorf("rawToken should be valid base64 URL encoding: %v", err)
	}
	if len(decoded) != 32 {
		t.Errorf("decoded token should be 32 bytes, got %d", len(decoded))
	}

	// Hash should match the hashToken function output
	expectedHash := hashToken(rawToken1)
	if hash1 != expectedHash {
		t.Errorf("hash mismatch: expected %s, got %s", expectedHash, hash1)
	}

	// Each call should generate different tokens
	rawToken2, hash2, err := generateResetToken()
	if err != nil {
		t.Fatalf("second generateResetToken failed: %v", err)
	}
	if rawToken1 == rawToken2 {
		t.Error("tokens should be unique")
	}
	if hash1 == hash2 {
		t.Error("hashes should be unique")
	}
}

func TestGenerateResetToken_Uniqueness(t *testing.T) {
	// Generate multiple tokens and verify uniqueness
	tokens := make(map[string]bool)
	hashes := make(map[string]bool)

	for i := 0; i < 100; i++ {
		rawToken, hash, err := generateResetToken()
		if err != nil {
			t.Fatalf("generateResetToken failed on iteration %d: %v", i, err)
		}

		if tokens[rawToken] {
			t.Errorf("duplicate token generated on iteration %d", i)
		}
		if hashes[hash] {
			t.Errorf("duplicate hash generated on iteration %d", i)
		}

		tokens[rawToken] = true
		hashes[hash] = true
	}
}
