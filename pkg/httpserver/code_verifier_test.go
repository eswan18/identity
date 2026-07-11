package httpserver

import (
	"strings"
	"testing"
)

// TestIsValidCodeVerifier exercises the length check applied to PKCE code
// verifiers before they are hashed and compared against the stored
// code_challenge: RFC 7636 §4.1 requires 43-128 characters. The character set
// is intentionally NOT enforced (see isValidCodeVerifier) — clients may send
// base64url values with '=' padding, and any unexpected characters simply fail
// the code_challenge comparison rather than being rejected here.
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
			name:     "padded base64url verifier is accepted (contains '=')",
			verifier: repeat("a", 43) + "=", // 44 chars; clients that pad must still work
			want:     true,
		},
		{
			name:     "base64 std-alphabet verifier is accepted ('+' and '/')",
			verifier: repeat("a", 42) + "+/", // 44 chars; charset is not enforced
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidCodeVerifier(tt.verifier); got != tt.want {
				t.Errorf("isValidCodeVerifier(%q) = %v, want %v (len=%d)", tt.verifier, got, tt.want, len(tt.verifier))
			}
		})
	}
}
