package jwt

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Generator generates and validates JWTs using ECDSA (ES256)
type Generator struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	issuer     string
	keyID      string
}

// Claims represents the JWT claims structure
type Claims struct {
	jwt.RegisteredClaims
	Username      string `json:"username"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Scope         string `json:"scope"`
}

// NewGenerator creates a new JWT generator from a PEM-encoded ECDSA private key
func NewGenerator(privateKeyPEM, issuer, keyID string) (*Generator, error) {
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
		keyID:      keyID,
	}, nil
}

// GenerateAccessToken creates a signed JWT access token
func (g *Generator) GenerateAccessToken(
	userID, username, email, audience string,
	emailVerified bool,
	scope []string,
	expiresIn time.Duration,
) (token string, jti string, err error) {
	now := time.Now()
	jti = uuid.New().String()

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    g.issuer,
			Subject:   userID,
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(expiresIn)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        jti,
		},
		Username:      username,
		Email:         email,
		EmailVerified: emailVerified,
		Scope:         joinScope(scope),
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
	return strings.Join(scope, " ")
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

// GenerateServiceAccountToken creates a signed JWT for service accounts (client credentials grant).
// Uses client_id as subject, omits user-specific claims (username, email).
func (g *Generator) GenerateServiceAccountToken(
	clientID, audience string,
	scope []string,
	expiresIn time.Duration,
) (token string, jti string, err error) {
	now := time.Now()
	jti = uuid.New().String()

	// For service accounts, we use a simpler claim structure without user info
	claims := jwt.MapClaims{
		"iss":   g.issuer,
		"sub":   clientID, // Client ID as subject for service accounts
		"aud":   audience,
		"exp":   now.Add(expiresIn).Unix(),
		"iat":   now.Unix(),
		"jti":   jti,
		"scope": joinScope(scope),
		// Note: No username, email, email_verified for service accounts
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	jwtToken.Header["kid"] = g.keyID

	signedToken, err := jwtToken.SignedString(g.privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedToken, jti, nil
}

// ValidateToken validates a JWT and returns its claims.
// If expectedAudience is non-empty, it validates that the token's audience contains it.
func (g *Generator) ValidateToken(tokenString string, expectedAudience string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method is exactly ES256 (not ES384 or ES512)
		if token.Method != jwt.SigningMethodES256 {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return g.publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Validate issuer
	if claims.Issuer != g.issuer {
		return nil, fmt.Errorf("invalid issuer: expected %s, got %s", g.issuer, claims.Issuer)
	}

	// Validate audience if expected audience is provided
	if expectedAudience != "" {
		audienceValid := false
		for _, aud := range claims.Audience {
			if aud == expectedAudience {
				audienceValid = true
				break
			}
		}
		if !audienceValid {
			return nil, fmt.Errorf("invalid audience: token not intended for %s", expectedAudience)
		}
	}

	return claims, nil
}
