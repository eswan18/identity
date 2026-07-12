package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestHashAndVerifyPassword(t *testing.T) {
	password := "mysecretpassword"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	// Verify correct password
	valid, err := VerifyPassword(password, hash)
	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
	if !valid {
		t.Error("VerifyPassword returned false for correct password")
	}

	// Verify wrong password
	valid, err = VerifyPassword("wrongpassword", hash)
	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
	if valid {
		t.Error("VerifyPassword returned true for wrong password")
	}
}

func TestHashPasswordUniqueSalts(t *testing.T) {
	password := "samepassword"

	hash1, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	hash2, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	// Same password should produce different hashes (different salts)
	if hash1 == hash2 {
		t.Error("HashPassword produced identical hashes for same password (salts should differ)")
	}

	// But both should verify correctly
	valid, _ := VerifyPassword(password, hash1)
	if !valid {
		t.Error("First hash doesn't verify")
	}
	valid, _ = VerifyPassword(password, hash2)
	if !valid {
		t.Error("Second hash doesn't verify")
	}
}

// buildEncodedHash constructs an argon2id encoded hash string using
// caller-supplied parameters, mirroring the format produced by
// HashPassword but without relying on the package's current constants.
func buildEncodedHash(password string, mem, iters uint32, par uint8, keyLen uint32) (string, error) {
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, iters, mem, par, keyLen)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, mem, iters, par, b64Salt, b64Hash), nil
}

// TestVerifyPasswordUsesHashEmbeddedParams proves that VerifyPassword
// derives its comparison hash from the memory/iterations/parallelism
// parameters embedded in the stored encoded hash, not from the package's
// current memory/iterations/parallelism constants. It builds a hash with
// parameters that are clearly different from the current constants; if
// VerifyPassword ignored the embedded params (the old, buggy behavior)
// this test would fail because the re-derived hash would use the wrong
// parameters and never match.
func TestVerifyPasswordUsesHashEmbeddedParams(t *testing.T) {
	password := "correct horse battery staple"

	// Sanity check: these custom params must differ from the current
	// package constants, or this test wouldn't actually exercise the fix.
	customMemory := uint32(32768)
	customIterations := uint32(2)
	customParallelism := uint8(1)
	if customMemory == uint32(memory) && customIterations == uint32(iterations) && customParallelism == uint8(parallelism) {
		t.Fatal("custom params must differ from package constants for this test to be meaningful")
	}

	hash, err := buildEncodedHash(password, customMemory, customIterations, customParallelism, keyLength)
	if err != nil {
		t.Fatalf("buildEncodedHash failed: %v", err)
	}

	valid, err := VerifyPassword(password, hash)
	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
	if !valid {
		t.Error("VerifyPassword returned false for a hash built with non-default params and the correct password")
	}

	valid, err = VerifyPassword("wrong password", hash)
	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
	if valid {
		t.Error("VerifyPassword returned true for a hash built with non-default params and a wrong password")
	}
}

func TestVerifyPasswordMalformedHash(t *testing.T) {
	password := "mysecretpassword"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	parts := strings.Split(hash, "$")

	cases := []struct {
		name string
		hash string
	}{
		{
			name: "bad version",
			hash: fmt.Sprintf("$%s$v=18$%s$%s$%s", parts[1], parts[3], parts[4], parts[5]),
		},
		{
			name: "non-numeric version",
			hash: fmt.Sprintf("$%s$v=abc$%s$%s$%s", parts[1], parts[3], parts[4], parts[5]),
		},
		{
			name: "non-numeric params",
			hash: fmt.Sprintf("$%s$%s$m=abc,t=3,p=2$%s$%s", parts[1], parts[2], parts[4], parts[5]),
		},
		{
			name: "too few parts",
			hash: fmt.Sprintf("$%s$%s$%s$%s", parts[1], parts[2], parts[3], parts[4]),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyPassword(password, tc.hash)
			if err == nil {
				t.Errorf("expected an error for malformed hash %q, got nil", tc.hash)
			}
		})
	}
}
