package httpserver

import (
	"testing"
)

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
