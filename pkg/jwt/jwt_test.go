package jwt

import (
	"encoding/base64"
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
		"test-client",
		true, // emailVerified
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
		"test-client",
		true, // emailVerified
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
		"test-client",
		false, // emailVerified
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
		"test-client",
		false, // emailVerified
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
		"test-client",
		false, // emailVerified
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
		"test-client",
		false, // emailVerified
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
		"test-client",
		false, // emailVerified
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

func TestGenerateIDToken(t *testing.T) {
	g, err := NewGenerator(testPrivateKey, "https://issuer.example.com", "key-1")
	if err != nil {
		t.Fatalf("NewGenerator failed: %v", err)
	}

	emailVerified := true
	idClaims := IDTokenClaims{
		Email:         "test@example.com",
		EmailVerified: &emailVerified,
		Username:      "testuser",
		GivenName:     "Test",
		FamilyName:    "User",
	}

	accessToken := "fake-access-token-for-at-hash"
	idToken, err := g.GenerateIDToken(
		"user-123",
		"my-client-id",
		accessToken,
		idClaims,
		time.Hour,
	)
	if err != nil {
		t.Fatalf("GenerateIDToken failed: %v", err)
	}

	// Parse and verify the ID token
	claims, err := g.ValidateToken(idToken, "my-client-id")
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}

	if claims.Subject != "user-123" {
		t.Errorf("expected sub %q, got %q", "user-123", claims.Subject)
	}
	if claims.Issuer != "https://issuer.example.com" {
		t.Errorf("expected issuer %q, got %q", "https://issuer.example.com", claims.Issuer)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "my-client-id" {
		t.Errorf("expected audience [my-client-id], got %v", claims.Audience)
	}

	// Verify ID-token-specific claims by parsing the raw payload
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}
	var rawClaims map[string]interface{}
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	json.Unmarshal(payload, &rawClaims)

	if rawClaims["email"] != "test@example.com" {
		t.Errorf("expected email %q, got %v", "test@example.com", rawClaims["email"])
	}
	if rawClaims["email_verified"] != true {
		t.Errorf("expected email_verified true, got %v", rawClaims["email_verified"])
	}
	if rawClaims["preferred_username"] != "testuser" {
		t.Errorf("expected preferred_username %q, got %v", "testuser", rawClaims["preferred_username"])
	}
	if rawClaims["given_name"] != "Test" {
		t.Errorf("expected given_name %q, got %v", "Test", rawClaims["given_name"])
	}
	if rawClaims["at_hash"] == nil || rawClaims["at_hash"] == "" {
		t.Error("expected non-empty at_hash")
	}
}

func TestGenerateIDToken_OmitsEmptyClaims(t *testing.T) {
	g, err := NewGenerator(testPrivateKey, "https://issuer.example.com", "key-1")
	if err != nil {
		t.Fatalf("NewGenerator failed: %v", err)
	}

	// No email or profile claims set
	idToken, err := g.GenerateIDToken(
		"user-123",
		"my-client-id",
		"fake-access-token",
		IDTokenClaims{},
		time.Hour,
	)
	if err != nil {
		t.Fatalf("GenerateIDToken failed: %v", err)
	}

	parts := strings.Split(idToken, ".")
	var rawClaims map[string]interface{}
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	json.Unmarshal(payload, &rawClaims)

	// These should be absent (omitempty)
	for _, key := range []string{"email", "email_verified", "preferred_username", "given_name", "family_name", "picture"} {
		if _, ok := rawClaims[key]; ok {
			t.Errorf("expected %q to be omitted, but it was present: %v", key, rawClaims[key])
		}
	}

	// These should always be present
	for _, key := range []string{"sub", "iss", "aud", "exp", "iat", "at_hash"} {
		if _, ok := rawClaims[key]; !ok {
			t.Errorf("expected %q to be present", key)
		}
	}
}

// decodeSegment returns one base64url segment of a compact JWT as raw JSON
// fields, so a test can assert on the exact bytes a resource server would see
// rather than on what a Go claims struct makes of them.
func decodeSegment(t *testing.T, token string, index int) map[string]json.RawMessage {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected a compact JWT with 3 parts, got %d", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[index])
	if err != nil {
		t.Fatalf("decoding JWT segment %d: %v", index, err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("parsing JWT segment %d: %v", index, err)
	}
	return fields
}

// TestAccessTokensFollowRFC9068 pins the access-token profile for both kinds
// of access token: header typ "at+jwt", a client_id claim, and aud as a
// one-element array -- including service-account tokens, whose aud used to be
// a bare string. The aud value is compared as raw JSON because the URN-style
// "ethanswan:fitness" must reach footstrike-api byte for byte.
func TestAccessTokensFollowRFC9068(t *testing.T) {
	g, err := NewGenerator(testPrivateKey, "https://issuer.example.com", "key-1")
	if err != nil {
		t.Fatalf("NewGenerator failed: %v", err)
	}

	userToken, _, err := g.GenerateAccessToken(
		"user-123", "testuser", "test@example.com", "ethanswan:fitness", "public-client-id",
		true, []string{"openid"}, time.Hour,
	)
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}
	serviceToken, _, err := g.GenerateServiceAccountToken(
		"service-client-id", "https://issuer.example.com", []string{"admin:users:read"}, time.Hour,
	)
	if err != nil {
		t.Fatalf("GenerateServiceAccountToken failed: %v", err)
	}

	cases := []struct {
		name, token, wantAud, wantClientID string
	}{
		{"user", userToken, `["ethanswan:fitness"]`, `"public-client-id"`},
		{"service account", serviceToken, `["https://issuer.example.com"]`, `"service-client-id"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			header := decodeSegment(t, c.token, 0)
			if got := string(header["typ"]); got != `"at+jwt"` {
				t.Errorf("header typ = %s, want \"at+jwt\"", got)
			}
			claims := decodeSegment(t, c.token, 1)
			if got := string(claims["aud"]); got != c.wantAud {
				t.Errorf("aud = %s, want %s", got, c.wantAud)
			}
			if got := string(claims["client_id"]); got != c.wantClientID {
				t.Errorf("client_id = %s, want %s", got, c.wantClientID)
			}

			parsed, err := g.ValidateToken(c.token, "")
			if err != nil {
				t.Fatalf("ValidateToken: %v", err)
			}
			if want := strings.Trim(c.wantClientID, `"`); parsed.ClientID != want {
				t.Errorf("Claims.ClientID = %q, want %q", parsed.ClientID, want)
			}
		})
	}

	// ID tokens are not access tokens and must not claim to be.
	idToken, err := g.GenerateIDToken("user-123", "public-client-id", userToken, IDTokenClaims{}, time.Hour)
	if err != nil {
		t.Fatalf("GenerateIDToken failed: %v", err)
	}
	if got := string(decodeSegment(t, idToken, 0)["typ"]); got == `"at+jwt"` {
		t.Errorf("ID token header typ = %s; only access tokens are at+jwt", got)
	}
	if got := string(decodeSegment(t, idToken, 1)["aud"]); got != `["public-client-id"]` {
		t.Errorf("ID token aud = %s, want the client_id", got)
	}
}
