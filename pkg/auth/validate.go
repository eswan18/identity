package auth

import (
	_ "embed"
	"errors"
	"regexp"
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

// ErrUsernameInvalid is returned by ValidateUsername for any username that
// doesn't match usernamePattern. The message states the rule rather than which
// part of it failed, because that's all a user needs in order to pick a valid
// name.
var ErrUsernameInvalid = errors.New("username must be 3-50 characters, using only letters, numbers, and underscores")

// usernamePattern is the single definition of an acceptable username. Keep the
// {3,50} bound in sync with ErrUsernameInvalid's wording above.
//
// This rule already existed, but only on the admin API
// (HandleAdminCreateUser), which recompiled it per request and which the
// self-service paths never call. Registration and change-username accepted
// anything non-empty, and the schema backs them with a bare `username text NOT
// NULL UNIQUE` -- no CHECK constraint, no length cap, no character class. A
// username is interpolated into HTML emails (see buildVerificationEmailHTML in
// pkg/httpserver/email_verification.go and the username reminder in
// pkg/httpserver/password_reset.go), so an unconstrained one was an injection
// vector into mail sent from our own domain. Restricting the character class
// removes the payload; escaping at those sinks removes the injection. Both are
// done -- neither alone is relied upon.
var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9_]{3,50}$`)

// ValidateUsername checks that a username is well-formed. It returns nil if
// valid, or ErrUsernameInvalid.
//
// It deliberately applies only where a username is being set (registration,
// change-username, admin creation). Existing accounts whose usernames predate
// this rule keep working: nothing revalidates on login, which looks a username
// up by exact string.
func ValidateUsername(username string) error {
	if !usernamePattern.MatchString(username) {
		return ErrUsernameInvalid
	}
	return nil
}

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
