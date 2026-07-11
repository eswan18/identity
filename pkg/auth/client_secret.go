package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

// HashClientSecret returns the lowercase hex-encoded SHA-256 hash of an OAuth
// client secret.
//
// Client secrets are high-entropy, randomly generated strings, so a fast
// cryptographic hash (SHA-256) is appropriate and sufficient here. Unlike
// low-entropy human passwords (which use argon2/bcrypt via HashPassword), there
// is no need for a slow, salted KDF: an attacker cannot feasibly brute-force a
// 32-byte random secret, and a fast hash keeps constant-time verification cheap.
//
// The output is lowercase hex with no prefix so that it matches Postgres'
// `encode(digest(secret, 'sha256'), 'hex')`, which lets the accompanying
// migration hash existing plaintext secrets in place.
func HashClientSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// ClientSecretMatches reports whether the presented plaintext secret hashes to
// the stored hash, using a constant-time comparison to avoid leaking timing
// information about the stored value.
func ClientSecretMatches(storedHash, presentedSecret string) bool {
	presentedHash := HashClientSecret(presentedSecret)
	return subtle.ConstantTimeCompare([]byte(storedHash), []byte(presentedHash)) == 1
}
