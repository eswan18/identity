package mfa

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

// TestKeyFromSecretRoundTrip verifies that a key reconstructed from a stored base32
// secret carries the same secret and produces codes that validate against it. This
// is what lets the enrollment retry page re-render a QR for the server-stored secret
// without generating a new one.
func TestKeyFromSecretRoundTrip(t *testing.T) {
	orig, err := GenerateSecret("alice")
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	secret := GetSecret(orig)

	rebuilt, err := KeyFromSecret("alice", secret)
	if err != nil {
		t.Fatalf("KeyFromSecret: %v", err)
	}

	if got := rebuilt.Secret(); got != secret {
		t.Fatalf("rebuilt secret = %q, want %q", got, secret)
	}

	// A code generated for the secret must validate, confirming the reconstructed
	// key uses the same TOTP parameters as the original.
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if !ValidateCode(rebuilt.Secret(), code) {
		t.Fatalf("code %q did not validate against reconstructed secret", code)
	}
}
