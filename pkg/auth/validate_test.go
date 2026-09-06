package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestValidatePassword_TooShort(t *testing.T) {
	testCases := []string{
		"",
		"a",
		"1234567",
		"short",
	}

	for _, tc := range testCases {
		err := ValidatePassword(tc, "someuser")
		if !errors.Is(err, ErrPasswordTooShort) {
			t.Errorf("ValidatePassword(%q) = %v, want ErrPasswordTooShort", tc, err)
		}
	}
}

func TestValidatePassword_TooLong(t *testing.T) {
	longPassword := strings.Repeat("a", 129)
	err := ValidatePassword(longPassword, "someuser")
	if !errors.Is(err, ErrPasswordTooLong) {
		t.Errorf("ValidatePassword(129 chars) = %v, want ErrPasswordTooLong", err)
	}

	// Exactly 128 should be valid
	exactlyMaxPassword := strings.Repeat("a", 128)
	err = ValidatePassword(exactlyMaxPassword, "someuser")
	if err != nil {
		t.Errorf("ValidatePassword(128 chars) = %v, want nil", err)
	}
}

func TestValidatePassword_TooCommon(t *testing.T) {
	// Only test common passwords that are >= 8 characters
	commonPasswords := []string{
		"password",
		"PASSWORD",
		"Password",
		"123456789",
		"12345678",
		"baseball",
		"trustno1",
		"iloveyou",
		"sunshine",
		"princess",
	}

	for _, tc := range commonPasswords {
		err := ValidatePassword(tc, "someuser")
		if !errors.Is(err, ErrPasswordTooCommon) {
			t.Errorf("ValidatePassword(%q) = %v, want ErrPasswordTooCommon", tc, err)
		}
	}
}

func TestValidatePassword_SameAsUsername(t *testing.T) {
	testCases := []struct {
		password string
		username string
	}{
		{"myusername", "myusername"},
		{"MyUsername", "myusername"},
		{"MYUSERNAME", "myusername"},
		{"testuser123", "TestUser123"},
	}

	for _, tc := range testCases {
		err := ValidatePassword(tc.password, tc.username)
		if !errors.Is(err, ErrPasswordSameAsUsername) {
			t.Errorf("ValidatePassword(%q, %q) = %v, want ErrPasswordSameAsUsername", tc.password, tc.username, err)
		}
	}
}

func TestValidatePassword_Valid(t *testing.T) {
	validPasswords := []struct {
		password string
		username string
	}{
		{"correcthorsebatterystaple", "someuser"},
		{"MyS3cur3P@ssw0rd!", "anotheruser"},
		{"this is a passphrase with spaces", "testuser"},
		{"xk9$mLp2vQ", "notthispassword"}, // 10 random chars, not common
		{strings.Repeat("x", 128), "user"},
	}

	for _, tc := range validPasswords {
		err := ValidatePassword(tc.password, tc.username)
		if err != nil {
			t.Errorf("ValidatePassword(%q, %q) = %v, want nil", tc.password, tc.username, err)
		}
	}
}

func TestCommonPasswordsLoaded(t *testing.T) {
	// Verify that the common passwords map was loaded
	if len(commonPasswords) == 0 {
		t.Error("commonPasswords map is empty, expected ~1000 entries")
	}

	if len(commonPasswords) < 900 || len(commonPasswords) > 1100 {
		t.Errorf("commonPasswords has %d entries, expected ~1000", len(commonPasswords))
	}
}

func TestValidateUsername(t *testing.T) {
	tests := []struct {
		name     string
		username string
		wantErr  bool
	}{
		// Accepted.
		{"simple lowercase", "testuser", false},
		{"mixed case", "TestUser", false},
		{"digits", "user123", false},
		{"underscores", "test_user_1", false},
		{"minimum length", "abc", false},
		{"maximum length", strings.Repeat("a", 50), false},

		// Length bounds.
		{"empty", "", true},
		{"too short", "ab", true},
		{"too long", strings.Repeat("a", 51), true},

		// Character class. These are the ones that matter: a username reaches
		// HTML email bodies, so anything that could carry markup must be
		// refused here.
		{"html tag", "<b>bold</b>", true},
		{"script tag", "<script>alert(1)</script>", true},
		{"anchor payload", `</p><a href="https://evil.example">click</a><p>`, true},
		{"angle bracket alone", "user<name", true},
		{"double quote", `user"name`, true},
		{"single quote", "user'name", true},
		{"ampersand", "user&name", true},
		{"space", "test user", true},
		{"leading space", " testuser", true},
		{"trailing newline", "testuser\n", true},
		{"embedded newline", "test\nuser", true},
		{"tab", "test\tuser", true},
		{"hyphen", "test-user", true},
		{"dot", "test.user", true},
		{"at sign", "user@example.com", true},
		{"slash", "test/user", true},
		{"percent", "test%user", true},
		{"null byte", "test\x00user", true},
		{"non-ascii", "tëstuser", true},
		{"emoji", "test👍user", true},
		{"rtl override", "test‮user", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUsername(tt.username)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateUsername(%q) error = %v, wantErr %v", tt.username, err, tt.wantErr)
			}
			if tt.wantErr && err != nil && !errors.Is(err, ErrUsernameInvalid) {
				t.Errorf("ValidateUsername(%q) = %v, want ErrUsernameInvalid", tt.username, err)
			}
		})
	}
}
