package auth

import "testing"

func TestHashClientSecretKnownVector(t *testing.T) {
	// Known-answer vector: SHA-256("abc") in lowercase hex. This is exactly what
	// Postgres produces via encode(digest('abc', 'sha256'), 'hex'), which is how
	// the 000010 migration hashes existing rows. Keeping this test in sync
	// guarantees the Go and SQL hashing agree, so migrated clients still
	// authenticate.
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := HashClientSecret("abc"); got != want {
		t.Fatalf("HashClientSecret(\"abc\") = %q, want %q", got, want)
	}
}

func TestHashClientSecretHexFormat(t *testing.T) {
	got := HashClientSecret("some-random-high-entropy-secret")
	if len(got) != 64 {
		t.Fatalf("expected 64 hex chars, got %d (%q)", len(got), got)
	}
	for _, c := range got {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("hash contains non-lowercase-hex character %q in %q", c, got)
		}
	}
}

func TestClientSecretMatches(t *testing.T) {
	secret := "cd9e459ea708a948d5c2f5a6ca8838cf" // arbitrary high-entropy value
	stored := HashClientSecret(secret)

	if !ClientSecretMatches(stored, secret) {
		t.Error("ClientSecretMatches returned false for the correct secret")
	}
	if ClientSecretMatches(stored, "wrong-secret") {
		t.Error("ClientSecretMatches returned true for an incorrect secret")
	}
	// A presented secret that happens to equal the stored hash must not match.
	if ClientSecretMatches(stored, stored) {
		t.Error("ClientSecretMatches returned true when presenting the stored hash itself")
	}
}
