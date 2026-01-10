package jwt

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testPrivateKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEICQMNHONu2Sud2tu6jgOZs3LIj5yOZr89NBMLYiyqBK/oAoGCCqGSM49
AwEHoUQDQgAERCHWHrX20emk31HypGNgptwBjdZOyBybV/9BLTbJPj8UsZ/46ri5
/eFKkRfNApxFU/5lk1RGQJqt8t0GvkkJdw==
-----END EC PRIVATE KEY-----`

func TestNewGenerator(t *testing.T) {
	g, err := NewGenerator(testPrivateKey, "https://issuer.example.com", "key-1")
	if err != nil {
		t.Fatalf("NewGenerator failed: %v", err)
	}
	if g.issuer != "https://issuer.example.com" {
		t.Errorf("expected issuer %q, got %q", "https://issuer.example.com", g.issuer)
	}
	if g.keyID != "key-1" {
		t.Errorf("expected keyID %q, got %q", "key-1", g.keyID)
	}
}

func TestNewGeneratorInvalidKey(t *testing.T) {
	_, err := NewGenerator("not a valid key", "https://issuer.example.com", "key-1")
	if err == nil {
		t.Error("expected error for invalid key, got nil")
	}
}

func TestGenerateAccessToken(t *testing.T) {
	g, err := NewGenerator(testPrivateKey, "https://issuer.example.com", "key-1")
	if err != nil {
		t.Fatalf("NewGenerator failed: %v", err)
	}

	token, jti, err := g.GenerateAccessToken(
		"user-123",
		"testuser",
		"test@example.com",
		"https://api.example.com",
		[]string{"openid", "profile"},
		time.Hour,
	)
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	// Token should be three base64 parts separated by dots
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Errorf("expected JWT with 3 parts, got %d", len(parts))
	}

	// JTI should be a non-empty UUID
	if jti == "" {
		t.Error("expected non-empty JTI")
	}
}

func TestGenerateAndValidateToken(t *testing.T) {
	g, err := NewGenerator(testPrivateKey, "https://issuer.example.com", "key-1")
	if err != nil {
		t.Fatalf("NewGenerator failed: %v", err)
	}

	token, _, err := g.GenerateAccessToken(
		"user-123",
		"testuser",
		"test@example.com",
		"https://api.example.com",
		[]string{"openid", "profile"},
		time.Hour,
	)
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	// Validate the token
	claims, err := g.ValidateToken(token, "https://api.example.com")
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}

	// Check claims
	if claims.Subject != "user-123" {
		t.Errorf("expected subject %q, got %q", "user-123", claims.Subject)
	}
	if claims.Username != "testuser" {
		t.Errorf("expected username %q, got %q", "testuser", claims.Username)
	}
	if claims.Email != "test@example.com" {
		t.Errorf("expected email %q, got %q", "test@example.com", claims.Email)
	}
	if claims.Scope != "openid profile" {
		t.Errorf("expected scope %q, got %q", "openid profile", claims.Scope)
	}
	if claims.Issuer != "https://issuer.example.com" {
		t.Errorf("expected issuer %q, got %q", "https://issuer.example.com", claims.Issuer)
	}
}

func TestValidateTokenRejectsExpired(t *testing.T) {
	g, err := NewGenerator(testPrivateKey, "https://issuer.example.com", "key-1")
	if err != nil {
		t.Fatalf("NewGenerator failed: %v", err)
	}

	// Generate a token that's already expired
	token, _, err := g.GenerateAccessToken(
		"user-123",
		"testuser",
		"test@example.com",
		"https://api.example.com",
		[]string{"openid"},
		-time.Hour, // negative duration = already expired
	)
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	_, err = g.ValidateToken(token, "https://api.example.com")
	if err == nil {
		t.Error("expected error for expired token, got nil")
	}
}

func TestValidateTokenRejectsWrongAudience(t *testing.T) {
	g, err := NewGenerator(testPrivateKey, "https://issuer.example.com", "key-1")
	if err != nil {
		t.Fatalf("NewGenerator failed: %v", err)
	}

	token, _, err := g.GenerateAccessToken(
		"user-123",
		"testuser",
		"test@example.com",
		"https://api.example.com",
		[]string{"openid"},
		time.Hour,
	)
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	// Validate with wrong audience
	_, err = g.ValidateToken(token, "https://wrong-audience.example.com")
	if err == nil {
		t.Error("expected error for wrong audience, got nil")
	}
	if !strings.Contains(err.Error(), "audience") {
		t.Errorf("expected audience error, got: %v", err)
	}
}

func TestValidateTokenRejectsWrongIssuer(t *testing.T) {
	g1, err := NewGenerator(testPrivateKey, "https://issuer1.example.com", "key-1")
	if err != nil {
		t.Fatalf("NewGenerator failed: %v", err)
	}

	g2, err := NewGenerator(testPrivateKey, "https://issuer2.example.com", "key-1")
	if err != nil {
		t.Fatalf("NewGenerator failed: %v", err)
	}

	// Generate token with issuer1
	token, _, err := g1.GenerateAccessToken(
		"user-123",
		"testuser",
		"test@example.com",
		"https://api.example.com",
		[]string{"openid"},
		time.Hour,
	)
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	// Validate with generator expecting issuer2
	_, err = g2.ValidateToken(token, "https://api.example.com")
	if err == nil {
		t.Error("expected error for wrong issuer, got nil")
	}
	if !strings.Contains(err.Error(), "issuer") {
		t.Errorf("expected issuer error, got: %v", err)
	}
}

func TestValidateTokenAcceptsEmptyExpectedAudience(t *testing.T) {
	g, err := NewGenerator(testPrivateKey, "https://issuer.example.com", "key-1")
	if err != nil {
		t.Fatalf("NewGenerator failed: %v", err)
	}

	token, _, err := g.GenerateAccessToken(
		"user-123",
		"testuser",
		"test@example.com",
		"https://api.example.com",
		[]string{"openid"},
		time.Hour,
	)
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	// Validate with empty audience (should skip audience check)
	claims, err := g.ValidateToken(token, "")
	if err != nil {
		t.Fatalf("ValidateToken with empty audience failed: %v", err)
	}
	if claims.Subject != "user-123" {
		t.Errorf("expected subject %q, got %q", "user-123", claims.Subject)
	}
}

func TestValidateTokenRejectsInvalidSignature(t *testing.T) {
	g, err := NewGenerator(testPrivateKey, "https://issuer.example.com", "key-1")
	if err != nil {
		t.Fatalf("NewGenerator failed: %v", err)
	}

	token, _, err := g.GenerateAccessToken(
		"user-123",
		"testuser",
		"test@example.com",
		"https://api.example.com",
		[]string{"openid"},
		time.Hour,
	)
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	// Tamper with the token by modifying the signature
	parts := strings.Split(token, ".")
	parts[2] = "invalidsignature"
	tamperedToken := strings.Join(parts, ".")

	_, err = g.ValidateToken(tamperedToken, "https://api.example.com")
	if err == nil {
		t.Error("expected error for invalid signature, got nil")
	}
}

func TestValidateTokenRejectsWrongAlgorithm(t *testing.T) {
	g, err := NewGenerator(testPrivateKey, "https://issuer.example.com", "key-1")
	if err != nil {
		t.Fatalf("NewGenerator failed: %v", err)
	}

	// Create a token with HS256 (HMAC) instead of ES256
	claims := jwt.MapClaims{
		"iss": "https://issuer.example.com",
		"sub": "user-123",
		"aud": []string{"https://api.example.com"},
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	hmacToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := hmacToken.SignedString([]byte("secret"))
	if err != nil {
		t.Fatalf("failed to create HMAC token: %v", err)
	}

	_, err = g.ValidateToken(tokenString, "https://api.example.com")
	if err == nil {
		t.Error("expected error for wrong algorithm, got nil")
	}
}

func TestPublicKeyJWKS(t *testing.T) {
	g, err := NewGenerator(testPrivateKey, "https://issuer.example.com", "key-1")
	if err != nil {
		t.Fatalf("NewGenerator failed: %v", err)
	}

	jwksBytes, err := g.PublicKeyJWKS()
	if err != nil {
		t.Fatalf("PublicKeyJWKS failed: %v", err)
	}

	// Parse the JWKS
	var jwks map[string]interface{}
	if err := json.Unmarshal(jwksBytes, &jwks); err != nil {
		t.Fatalf("failed to unmarshal JWKS: %v", err)
	}

	// Check structure
	keys, ok := jwks["keys"].([]interface{})
	if !ok {
		t.Fatal("JWKS missing 'keys' array")
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}

	key := keys[0].(map[string]interface{})

	// Verify required fields
	expectedFields := map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"kid": "key-1",
		"use": "sig",
		"alg": "ES256",
	}
	for field, expected := range expectedFields {
		if val, ok := key[field].(string); !ok || val != expected {
			t.Errorf("expected %s=%q, got %q", field, expected, val)
		}
	}

	// Verify x and y coordinates are present and non-empty
	if x, ok := key["x"].(string); !ok || x == "" {
		t.Error("JWKS key missing 'x' coordinate")
	}
	if y, ok := key["y"].(string); !ok || y == "" {
		t.Error("JWKS key missing 'y' coordinate")
	}
}

func TestJoinScope(t *testing.T) {
	tests := []struct {
		input    []string
		expected string
	}{
		{[]string{}, ""},
		{[]string{"openid"}, "openid"},
		{[]string{"openid", "profile"}, "openid profile"},
		{[]string{"openid", "profile", "email"}, "openid profile email"},
	}

	for _, tt := range tests {
		result := joinScope(tt.input)
		if result != tt.expected {
			t.Errorf("joinScope(%v) = %q, expected %q", tt.input, result, tt.expected)
		}
	}
}
