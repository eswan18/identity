package auth

import (
	_ "embed"
	"errors"
	"strings"
)

const (
	MinPasswordLength = 8
	MaxPasswordLength = 128
)

// Password validation errors
var (
	ErrPasswordTooShort    = errors.New("password must be at least 8 characters")
	ErrPasswordTooLong     = errors.New("password must be at most 128 characters")
	ErrPasswordTooCommon   = errors.New("password is too common")
	ErrPasswordSameAsUsername = errors.New("password cannot be the same as username")
)

//go:embed common_passwords.txt
var commonPasswordsData string

var commonPasswords map[string]struct{}

func init() {
	commonPasswords = make(map[string]struct{})
	for _, line := range strings.Split(commonPasswordsData, "\n") {
		password := strings.TrimSpace(line)
		if password != "" {
			commonPasswords[strings.ToLower(password)] = struct{}{}
		}
	}
}

// ValidatePassword checks if a password meets all requirements.
// Returns nil if valid, or a specific error describing the validation failure.
func ValidatePassword(password, username string) error {
	if len(password) < MinPasswordLength {
		return ErrPasswordTooShort
	}

	if len(password) > MaxPasswordLength {
		return ErrPasswordTooLong
	}

	// Case-insensitive check against common passwords
	if _, found := commonPasswords[strings.ToLower(password)]; found {
		return ErrPasswordTooCommon
	}

	// Case-insensitive check that password isn't the same as username
	if strings.EqualFold(password, username) {
		return ErrPasswordSameAsUsername
	}

	return nil
}
