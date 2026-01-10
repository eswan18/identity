package jwt

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Generator generates and validates JWTs using ECDSA (ES256)
type Generator struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	issuer     string
	audience   string
	keyID      string
}

// Claims represents the JWT claims structure
type Claims struct {
	jwt.RegisteredClaims
	Username string `json:"username"`
	Email    string `json:"email"`
	Scope    string `json:"scope"`
}

// NewGenerator creates a new JWT generator from a PEM-encoded ECDSA private key
func NewGenerator(privateKeyPEM, issuer, audience, keyID string) (*Generator, error) {
	// Parse PEM block
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing private key")
	}

	// Parse ECDSA private key
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ECDSA private key: %w", err)
	}

	return &Generator{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		issuer:     issuer,
		audience:   audience,
		keyID:      keyID,
	}, nil
}

// GenerateAccessToken creates a signed JWT access token
func (g *Generator) GenerateAccessToken(
	userID, username, email string,
	scope []string,
	expiresIn time.Duration,
) (token string, jti string, err error) {
	now := time.Now()
	jti = uuid.New().String()

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    g.issuer,
			Subject:   userID,
			Audience:  jwt.ClaimStrings{g.audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(expiresIn)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        jti,
		},
		Username: username,
		Email:    email,
		Scope:    joinScope(scope),
	}

	// Create token with ES256 signing method
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	jwtToken.Header["kid"] = g.keyID

	// Sign the token
	signedToken, err := jwtToken.SignedString(g.privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedToken, jti, nil
}

// PublicKeyJWKS returns the public key in JWKS format
func (g *Generator) PublicKeyJWKS() ([]byte, error) {
	// Get the x and y coordinates from the public key
	xBytes := g.publicKey.X.Bytes()
	yBytes := g.publicKey.Y.Bytes()

	// ECDSA P-256 coordinates should be 32 bytes, pad if necessary
	xBytes = padTo32Bytes(xBytes)
	yBytes = padTo32Bytes(yBytes)

	// Base64 URL encode without padding
	x := base64.RawURLEncoding.EncodeToString(xBytes)
	y := base64.RawURLEncoding.EncodeToString(yBytes)

	jwks := map[string]interface{}{
		"keys": []map[string]string{
			{
				"kty": "EC",
				"crv": "P-256",
				"x":   x,
				"y":   y,
				"kid": g.keyID,
				"use": "sig",
				"alg": "ES256",
			},
		},
	}

	return json.Marshal(jwks)
}

// joinScope converts a slice of scopes to a space-separated string
func joinScope(scope []string) string {
	if len(scope) == 0 {
		return ""
	}
	result := scope[0]
	for i := 1; i < len(scope); i++ {
		result += " " + scope[i]
	}
	return result
}

// padTo32Bytes pads a byte slice to 32 bytes (required for P-256 coordinates)
func padTo32Bytes(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}
