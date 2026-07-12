package httpserver

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/eswan18/identity/pkg/views"
)

// testTemplatesDir mirrors the relative path used by other package tests
// (see login_test.go) to point at the repo's templates/ directory.
const testTemplatesDir = "../../templates"

// requireContainsAll fails the test with a helpful message for any substring
// missing from html.
func requireContainsAll(t *testing.T, html string, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if !strings.Contains(html, s) {
			t.Errorf("expected rendered output to contain %q, but it did not.\n--- rendered output ---\n%s", s, html)
		}
	}
}

// render parses the given page together with base.html/partials.html exactly
// the way Server.New does, executes it with data, and returns the output.
// It fails the test immediately on any parse or execute error.
func render(t *testing.T, page string, data any) string {
	t.Helper()
	tmpl := mustParsePageTemplate(testTemplatesDir, page)
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		t.Fatalf("executing %s: %v", page, err)
	}
	return buf.String()
}

func TestPageTemplatesRenderLogin(t *testing.T) {
	// Plain error branch.
	html := render(t, "login.html", LoginPageData{
		Error:               "Invalid username or password",
		ClientID:            "client-abc",
		RedirectURI:         "https://example.com/callback",
		State:               "state-123",
		Scope:               []string{"openid", "profile"},
		CodeChallenge:       "challenge-xyz",
		CodeChallengeMethod: "S256",
		Nonce:               "nonce-1",
		CSRFToken:           "csrf-token-value",
	})
	requireContainsAll(t, html,
		"<!DOCTYPE html>",
		"<title>Sign In</title>",
		`action="/oauth/login"`,
		`name="csrf_token" value="csrf-token-value"`,
		"Invalid username or password",
		`alert-error`,
		"client-abc",
		"nonce-1",
	)
	if strings.Contains(html, "alert-success") {
		t.Errorf("plain error should not render the success alert styling")
	}

	// Special-cased success-styled message (uses .Error, not .Success).
	html = render(t, "login.html", LoginPageData{
		Error:     "Account created successfully! Please check your email to verify your account.",
		CSRFToken: "csrf-2",
	})
	requireContainsAll(t, html, "alert-success", "Account created successfully! Please check your email to verify your account.")
}

func TestPageTemplatesRenderRegister(t *testing.T) {
	html := render(t, "register.html", RegisterPageData{
		Error:               "Username already taken",
		Username:            "alice",
		Email:               "alice@example.com",
		ClientID:            "client-abc",
		RedirectURI:         "https://example.com/callback",
		State:               "state-1",
		Scope:               []string{"openid"},
		CodeChallenge:       "chal",
		CodeChallengeMethod: "S256",
		CSRFToken:           "csrf-register",
	})
	requireContainsAll(t, html,
		"<!DOCTYPE html>",
		"<title>Sign Up</title>",
		`action="/oauth/register"`,
		`name="csrf_token" value="csrf-register"`,
		"Username already taken",
		`value="alice"`,
		`value="alice@example.com"`,
	)
	if strings.Contains(html, "function previewImage") {
		t.Errorf("register.html should not contain change-avatar's script")
	}
}

func TestPageTemplatesRenderError(t *testing.T) {
	html := render(t, "error.html", ErrorPageData{
		Title:       "Invalid Request",
		Message:     "The request could not be completed.",
		Details:     "missing redirect_uri",
		ErrorCode:   "E123",
		RedirectURI: "https://example.com/back",
	})
	requireContainsAll(t, html,
		"<!DOCTYPE html>",
		"<title>Error</title>",
		"Invalid Request",
		"The request could not be completed.",
		"missing redirect_uri",
		"Error code: E123",
		`href="https://example.com/back"`,
		"card-body text-center",
	)
}

func TestPageTemplatesRenderSuccess(t *testing.T) {
	html := render(t, "success.html", struct{ CSRFToken string }{CSRFToken: "csrf-success"})
	requireContainsAll(t, html,
		"<!DOCTYPE html>",
		"<title>Login Successful</title>",
		`action="/oauth/logout"`,
		`name="csrf_token" value="csrf-success"`,
	)
}

func TestPageTemplatesRenderAccountSettings(t *testing.T) {
	html := render(t, "account-settings.html", AccountSettingsPageData{
		Error:         "",
		Success:       "Password updated",
		Username:      "bob",
		Email:         "bob@example.com",
		Name:          "Bob Bobson",
		AvatarURL:     "",
		IsInactive:    false,
		MfaEnabled:    true,
		EmailVerified: true,
		CSRFToken:     "csrf-acct",
	})
	requireContainsAll(t, html,
		"<!DOCTYPE html>",
		"<title>Account Settings</title>",
		"Password updated",
		"bob",
		"bob@example.com",
		"Bob Bobson",
		`name="csrf_token" value="csrf-acct"`,
		"Enabled", // MFA enabled badge
		"Danger Zone",
	)
}

// TestPageTemplatesRenderChangePassword covers the change-password page, which
// has been migrated from html/template to a templ component (pkg/views). Instead
// of parsing an .html file by name, it renders the typed component directly.
func TestPageTemplatesRenderChangePassword(t *testing.T) {
	var buf bytes.Buffer
	err := views.ChangePassword(views.ChangePasswordView{
		Error:     "Current password is incorrect",
		CSRFToken: "csrf-cp",
	}).Render(context.Background(), &buf)
	if err != nil {
		t.Fatalf("rendering ChangePassword component: %v", err)
	}
	requireContainsAll(t, buf.String(),
		"<!doctype html>",
		"<title>Change Password</title>",
		`action="/oauth/change-password"`,
		`name="csrf_token" value="csrf-cp"`,
		"Current password is incorrect",
	)
}

func TestPageTemplatesRenderChangeUsername(t *testing.T) {
	html := render(t, "change-username.html", ChangeUsernamePageData{
		Success:         "Username updated",
		CurrentUsername: "olduser",
		CSRFToken:       "csrf-cu",
	})
	requireContainsAll(t, html,
		"<!DOCTYPE html>",
		"<title>Change Username</title>",
		"Username updated",
		"olduser",
		`name="csrf_token" value="csrf-cu"`,
	)
}

func TestPageTemplatesRenderChangeEmail(t *testing.T) {
	html := render(t, "change-email.html", ChangeEmailPageData{
		Error:        "Email already in use",
		CurrentEmail: "old@example.com",
		CSRFToken:    "csrf-ce",
	})
	requireContainsAll(t, html,
		"<!DOCTYPE html>",
		"<title>Change Email</title>",
		"Email already in use",
		"old@example.com",
		`name="csrf_token" value="csrf-ce"`,
	)
}

func TestPageTemplatesRenderMFA(t *testing.T) {
	html := render(t, "mfa.html", MFAPageData{
		Error:               "Invalid code",
		PendingID:           "pending-123",
		ClientID:            "client-abc",
		RedirectURI:         "https://example.com/cb",
		State:               "state-9",
		Scope:               []string{"openid"},
		CodeChallenge:       "chal",
		CodeChallengeMethod: "S256",
		Nonce:               "nonce-9",
		CSRFToken:           "csrf-mfa",
	})
	requireContainsAll(t, html,
		"<!DOCTYPE html>",
		"<title>Two-Factor Authentication</title>",
		`action="/oauth/mfa"`,
		`name="csrf_token" value="csrf-mfa"`,
		"Invalid code",
		"pending-123",
	)
}

func TestPageTemplatesRenderMFASetup(t *testing.T) {
	html := render(t, "mfa-setup.html", MFASetupPageData{
		QRCode:    "ZmFrZS1xci1kYXRh",
		Secret:    "JBSWY3DPEHPK3PXP",
		CSRFToken: "csrf-mfasetup",
	})
	requireContainsAll(t, html,
		"<!DOCTYPE html>",
		"<title>Set Up Two-Factor Authentication</title>",
		`action="/oauth/mfa-setup"`,
		`name="csrf_token" value="csrf-mfasetup"`,
		"data:image/png;base64,ZmFrZS1xci1kYXRh",
		"JBSWY3DPEHPK3PXP",
	)
}

func TestPageTemplatesRenderForgotPassword(t *testing.T) {
	// Form branch (no success message yet).
	html := render(t, "forgot-password.html", ForgotPasswordPageData{CSRFToken: "csrf-fp"})
	requireContainsAll(t, html,
		"<!DOCTYPE html>",
		"<title>Forgot Password</title>",
		`action="/oauth/forgot-password"`,
		`name="csrf_token" value="csrf-fp"`,
	)

	// Success branch (form should be hidden).
	html = render(t, "forgot-password.html", ForgotPasswordPageData{Success: "Check your email", CSRFToken: "csrf-fp2"})
	requireContainsAll(t, html, "Check your email")
	if strings.Contains(html, `action="/oauth/forgot-password"`) {
		t.Errorf("expected form to be hidden once .Success is set")
	}
}

func TestPageTemplatesRenderForgotUsername(t *testing.T) {
	html := render(t, "forgot-username.html", ForgotPasswordPageData{CSRFToken: "csrf-fu"})
	requireContainsAll(t, html,
		"<!DOCTYPE html>",
		"<title>Forgot Username</title>",
		`action="/oauth/forgot-username"`,
		`name="csrf_token" value="csrf-fu"`,
	)
}

func TestPageTemplatesRenderResetPassword(t *testing.T) {
	html := render(t, "reset-password.html", ResetPasswordPageData{
		Error:     "Token expired",
		Token:     "reset-token-xyz",
		CSRFToken: "csrf-rp",
	})
	requireContainsAll(t, html,
		"<!DOCTYPE html>",
		"<title>Reset Password</title>",
		`action="/oauth/reset-password"`,
		`name="csrf_token" value="csrf-rp"`,
		`name="token" value="reset-token-xyz"`,
		"Token expired",
	)
}

func TestPageTemplatesRenderEditProfile(t *testing.T) {
	html := render(t, "edit-profile.html", EditProfilePageData{
		Success:    "Profile saved",
		GivenName:  "Ada",
		FamilyName: "Lovelace",
		CSRFToken:  "csrf-ep",
	})
	requireContainsAll(t, html,
		"<!DOCTYPE html>",
		"<title>Edit Profile</title>",
		"Profile saved",
		`value="Ada"`,
		`value="Lovelace"`,
		`name="csrf_token" value="csrf-ep"`,
	)
}

func TestPageTemplatesRenderChangeAvatar(t *testing.T) {
	html := render(t, "change-avatar.html", ChangeAvatarPageData{
		Success:   "Avatar updated",
		AvatarURL: "https://example.com/avatar.png",
		CSRFToken: "csrf-ca",
	})
	requireContainsAll(t, html,
		"<!DOCTYPE html>",
		"<title>Change Avatar</title>",
		"Avatar updated",
		"https://example.com/avatar.png",
		`name="csrf_token" value="csrf-ca"`,
		"function previewImage",
	)
}

func TestPageTemplatesRenderConsent(t *testing.T) {
	html := render(t, "consent.html", ConsentPageData{
		ClientName:  "Example App",
		ClientID:    "client-abc",
		RedirectURI: "https://example.com/cb",
		State:       "state-5",
		Scope:       []string{"openid", "email"},
		ScopeDescriptions: []ScopeDescription{
			{Scope: "openid", Description: "Verify your identity"},
			{Scope: "email", Description: "View your email address"},
		},
		CodeChallenge:       "chal",
		CodeChallengeMethod: "S256",
		Nonce:               "nonce-5",
		ResponseType:        "code",
		CSRFToken:           "csrf-consent",
	})
	requireContainsAll(t, html,
		"<!DOCTYPE html>",
		"<title>Authorize Application</title>",
		"Example App",
		"Verify your identity",
		"View your email address",
		`name="csrf_token" value="csrf-consent"`,
		`action="/oauth/consent"`,
	)
}

// TestPageTemplatesAllHaveFooterAndDoctype is a lightweight smoke test that
// every page template composes cleanly with base.html + partials.html and
// renders the shared skeleton once.
func TestPageTemplatesAllHaveFooterAndDoctype(t *testing.T) {
	pages := []struct {
		name string
		data any
	}{
		{"login.html", LoginPageData{CSRFToken: "t"}},
		{"register.html", RegisterPageData{CSRFToken: "t"}},
		{"error.html", ErrorPageData{}},
		{"success.html", struct{ CSRFToken string }{CSRFToken: "t"}},
		{"account-settings.html", AccountSettingsPageData{CSRFToken: "t"}},
		// change-password is a templ component now (see TestPageTemplatesRenderChangePassword).
		{"change-username.html", ChangeUsernamePageData{CSRFToken: "t"}},
		{"change-email.html", ChangeEmailPageData{CSRFToken: "t"}},
		{"mfa.html", MFAPageData{CSRFToken: "t"}},
		{"mfa-setup.html", MFASetupPageData{CSRFToken: "t"}},
		{"forgot-password.html", ForgotPasswordPageData{CSRFToken: "t"}},
		{"reset-password.html", ResetPasswordPageData{CSRFToken: "t"}},
		{"forgot-username.html", ForgotPasswordPageData{CSRFToken: "t"}},
		{"edit-profile.html", EditProfilePageData{CSRFToken: "t"}},
		{"change-avatar.html", ChangeAvatarPageData{CSRFToken: "t"}},
		{"consent.html", ConsentPageData{CSRFToken: "t"}},
	}
	for _, p := range pages {
		t.Run(p.name, func(t *testing.T) {
			html := render(t, p.name, p.data)
			requireContainsAll(t, html,
				"<!DOCTYPE html>",
				`<link rel="stylesheet" href="/static/style.css">`,
				"Identity Service", // shared footer partial
				`<div class="divider"></div>`,
			)
			if !strings.HasSuffix(strings.TrimSpace(html), "</html>") {
				t.Errorf("%s: expected output to end with </html>, got tail: %q", p.name, tail(html, 80))
			}
		})
	}
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
