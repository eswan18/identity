package auth

import (
	"testing"
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
