package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	memory      = 64 * 1024 // 64 MB
	iterations  = 3
	parallelism = 2
	keyLength   = 32
	saltLength  = 16
)

// HashPassword hashes a password using argon2id
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, keyLength)

	// Encode to base64
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Format: $argon2id$v=19$m=65536,t=3,p=2$salt$hash
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memory, iterations, parallelism, b64Salt, b64Hash), nil
}

// VerifyPassword verifies a password against an encoded hash
func VerifyPassword(password, encodedHash string) (bool, error) {
	// Parse the encoded hash
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, fmt.Errorf("invalid hash format")
	}

	// Parse and validate the version field, e.g. "v=19"
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, fmt.Errorf("invalid hash format")
	}
	if version != argon2.Version {
		return false, fmt.Errorf("incompatible argon2 version")
	}

	// Parse the parameters embedded in the hash, e.g. "m=65536,t=3,p=2".
	// These reflect whatever memory/iterations/parallelism were in effect
	// when this particular hash was created, which may differ from the
	// package's current constants.
	var hashMemory, hashIterations uint32
	var hashParallelism uint8
	if n, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &hashMemory, &hashIterations, &hashParallelism); err != nil || n != 3 {
		return false, fmt.Errorf("invalid hash format")
	}

	// Decode salt and hash
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}

	// Verify using the parameters parsed from the stored hash, not the
	// package's current constants, so that changing the current
	// memory/iterations/parallelism defaults doesn't break verification
	// of existing hashes.
	otherHash := argon2.IDKey([]byte(password), salt, hashIterations, hashMemory, hashParallelism, uint32(len(hash)))
	return subtle.ConstantTimeCompare(hash, otherHash) == 1, nil
}
