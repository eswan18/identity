// Package mfa provides TOTP-based multi-factor authentication utilities.
package mfa

import (
	"bytes"
	"encoding/base64"
	"image/png"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	// Issuer is the name shown in authenticator apps
	Issuer = "Identity"
	// SecretSize is the size of the TOTP secret in bytes
	SecretSize = 20
)

// GenerateSecret creates a new TOTP secret for a user.
// Returns the secret key and the otpauth URL for QR code generation.
func GenerateSecret(username string) (*otp.Key, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      Issuer,
		AccountName: username,
		SecretSize:  SecretSize,
	})
	if err != nil {
		return nil, err
	}
	return key, nil
}

// GenerateQRCode generates a QR code image as a base64-encoded PNG string.
// The QR code can be scanned by authenticator apps like Google Authenticator or Authy.
func GenerateQRCode(key *otp.Key) (string, error) {
	img, err := key.Image(200, 200)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// ValidateCode validates a TOTP code against a secret.
// It accepts codes within ±1 time step (30 seconds) to account for clock skew.
func ValidateCode(secret, code string) bool {
	return totp.Validate(code, secret)
}

// GetSecret returns the base32-encoded secret from an OTP key.
func GetSecret(key *otp.Key) string {
	return key.Secret()
}

// GetProvisioningURI returns the otpauth:// URI for manual entry.
func GetProvisioningURI(key *otp.Key) string {
	return key.URL()
}
