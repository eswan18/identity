package httpserver

import (
	"strings"
	"testing"
)

// TestIsValidCodeVerifier exercises the RFC 7636 §4.1 shape check applied to
// PKCE code verifiers before they are hashed and compared against the stored
// code_challenge: 43-128 characters drawn from the unreserved character set
// (ALPHA / DIGIT / "-" / "." / "_" / "~").
func TestIsValidCodeVerifier(t *testing.T) {
	repeat := func(s string, n int) string { return strings.Repeat(s, n) }

	tests := []struct {
		name     string
		verifier string
		want     bool
	}{
		{
			name:     "valid 43-char verifier",
			verifier: repeat("a", 43),
			want:     true,
		},
		{
			name:     "valid 128-char verifier",
			verifier: repeat("a", 128),
			want:     true,
		},
		{
			name:     "valid verifier with all allowed punctuation",
			verifier: repeat("A-b.c_d~9", 5), // 45 chars, mixes '-', '.', '_', '~'
			want:     true,
		},
		{
			name:     "too short (42 chars)",
			verifier: repeat("a", 42),
			want:     false,
		},
		{
			name:     "too long (129 chars)",
			verifier: repeat("a", 129),
			want:     false,
		},
		{
			name:     "empty string",
			verifier: "",
			want:     false,
		},
		{
			name:     "contains disallowed character (plus sign)",
			verifier: repeat("a", 42) + "+",
			want:     false,
		},
		{
			name:     "contains disallowed character (slash, base64 std alphabet)",
			verifier: repeat("a", 42) + "/",
			want:     false,
		},
		{
			name:     "contains whitespace",
			verifier: repeat("a", 21) + " " + repeat("a", 21),
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidCodeVerifier(tt.verifier); got != tt.want {
				t.Errorf("isValidCodeVerifier(%q) = %v, want %v (len=%d)", tt.verifier, got, tt.want, len(tt.verifier))
			}
		})
	}
}
