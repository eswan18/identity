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

// TestPageTemplatesRenderRegister covers the register page, which has been
// migrated from html/template to a templ component (pkg/views). Instead of
// parsing an .html file by name, it renders the typed component directly. It
// also verifies the OAuth hidden fields (joined scope included) and the
// inline password-match script (with its registerForm/password/
// confirm_password/passwordError element IDs) render via Layout's new
// scripts slot.
func TestPageTemplatesRenderRegister(t *testing.T) {
	var buf bytes.Buffer
	err := views.Register(views.RegisterView{
		Error:               "Username already taken",
		Username:            "alice",
		Email:               "alice@example.com",
		ClientID:            "client-abc",
		RedirectURI:         "https://example.com/callback",
		State:               "state-1",
		Scope:               []string{"openid", "profile"},
		CodeChallenge:       "chal",
		CodeChallengeMethod: "S256",
		CSRFToken:           "csrf-register",
	}).Render(context.Background(), &buf)
	if err != nil {
		t.Fatalf("rendering Register component: %v", err)
	}
	html := buf.String()
	requireContainsAll(t, html,
		"<!doctype html>",
		"<title>Sign Up</title>",
		`action="/oauth/register" id="registerForm"`,
		`name="csrf_token" value="csrf-register"`,
		"Username already taken",
		`value="alice"`,
		`value="alice@example.com"`,
		`name="client_id" value="client-abc"`,
		`name="redirect_uri" value="https://example.com/callback"`,
		`name="state" value="state-1"`,
		`name="scope" value="openid profile"`,
		`name="code_challenge" value="chal"`,
		`name="code_challenge_method" value="S256"`,
		`id="password"`,
		`id="confirm_password"`,
		`id="passwordError"`,
		"function validatePasswords",
	)
	if strings.Contains(html, "function previewImage") {
		t.Errorf("register component should not contain change-avatar's script")
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

// TestPageTemplatesRenderSuccess covers the success page, which has been
// migrated from html/template to a templ component (pkg/views). Instead of
// parsing an .html file by name, it renders the typed component directly.
func TestPageTemplatesRenderSuccess(t *testing.T) {
	var buf bytes.Buffer
	err := views.Success(views.SuccessView{CSRFToken: "csrf-success"}).Render(context.Background(), &buf)
	if err != nil {
		t.Fatalf("rendering Success component: %v", err)
	}
	requireContainsAll(t, buf.String(),
		"<!doctype html>",
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

// TestPageTemplatesRenderChangeUsername covers the change-username page, which
// has been migrated from html/template to a templ component (pkg/views). Instead
// of parsing an .html file by name, it renders the typed component directly.
func TestPageTemplatesRenderChangeUsername(t *testing.T) {
	var buf bytes.Buffer
	err := views.ChangeUsername(views.ChangeUsernameView{
		Success:         "Username updated",
		CurrentUsername: "olduser",
		CSRFToken:       "csrf-cu",
	}).Render(context.Background(), &buf)
	if err != nil {
		t.Fatalf("rendering ChangeUsername component: %v", err)
	}
	requireContainsAll(t, buf.String(),
		"<!doctype html>",
		"<title>Change Username</title>",
		"Username updated",
		"olduser",
		`name="csrf_token" value="csrf-cu"`,
	)
}

// TestPageTemplatesRenderChangeEmail covers the change-email page, which has
// been migrated from html/template to a templ component (pkg/views). Instead
// of parsing an .html file by name, it renders the typed component directly.
func TestPageTemplatesRenderChangeEmail(t *testing.T) {
	var buf bytes.Buffer
	err := views.ChangeEmail(views.ChangeEmailView{
		Error:        "Email already in use",
		CurrentEmail: "old@example.com",
		CSRFToken:    "csrf-ce",
	}).Render(context.Background(), &buf)
	if err != nil {
		t.Fatalf("rendering ChangeEmail component: %v", err)
	}
	requireContainsAll(t, buf.String(),
		"<!doctype html>",
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

// TestPageTemplatesRenderForgotPassword covers the forgot-password page, which
// has been migrated from html/template to a templ component (pkg/views).
// Instead of parsing an .html file by name, it renders the typed component
// directly.
func TestPageTemplatesRenderForgotPassword(t *testing.T) {
	// Form branch (no success message yet).
	var buf bytes.Buffer
	err := views.ForgotPassword(views.ForgotPasswordView{CSRFToken: "csrf-fp"}).Render(context.Background(), &buf)
	if err != nil {
		t.Fatalf("rendering ForgotPassword component: %v", err)
	}
	requireContainsAll(t, buf.String(),
		"<!doctype html>",
		"<title>Forgot Password</title>",
		`action="/oauth/forgot-password"`,
		`name="csrf_token" value="csrf-fp"`,
	)

	// Success branch (form should be hidden).
	buf.Reset()
	err = views.ForgotPassword(views.ForgotPasswordView{Success: "Check your email", CSRFToken: "csrf-fp2"}).Render(context.Background(), &buf)
	if err != nil {
		t.Fatalf("rendering ForgotPassword component: %v", err)
	}
	requireContainsAll(t, buf.String(), "Check your email")
	if strings.Contains(buf.String(), `action="/oauth/forgot-password"`) {
		t.Errorf("expected form to be hidden once .Success is set")
	}
}

// TestPageTemplatesRenderForgotUsername covers the forgot-username page,
// which has been migrated from html/template to a templ component
// (pkg/views). It shares views.ForgotPasswordView with ForgotPassword above.
func TestPageTemplatesRenderForgotUsername(t *testing.T) {
	// Form branch (no success message yet).
	var buf bytes.Buffer
	err := views.ForgotUsername(views.ForgotPasswordView{CSRFToken: "csrf-fu"}).Render(context.Background(), &buf)
	if err != nil {
		t.Fatalf("rendering ForgotUsername component: %v", err)
	}
	requireContainsAll(t, buf.String(),
		"<!doctype html>",
		"<title>Forgot Username</title>",
		`action="/oauth/forgot-username"`,
		`name="csrf_token" value="csrf-fu"`,
	)

	// Success branch (form should be hidden).
	buf.Reset()
	err = views.ForgotUsername(views.ForgotPasswordView{Success: "Check your email for your username", CSRFToken: "csrf-fu2"}).Render(context.Background(), &buf)
	if err != nil {
		t.Fatalf("rendering ForgotUsername component: %v", err)
	}
	requireContainsAll(t, buf.String(), "Check your email for your username")
	if strings.Contains(buf.String(), `action="/oauth/forgot-username"`) {
		t.Errorf("expected form to be hidden once .Success is set")
	}
}

// TestPageTemplatesRenderResetPassword covers the reset-password page, which
// has been migrated from html/template to a templ component (pkg/views).
// Instead of parsing an .html file by name, it renders the typed component
// directly.
func TestPageTemplatesRenderResetPassword(t *testing.T) {
	var buf bytes.Buffer
	err := views.ResetPassword(views.ResetPasswordView{
		Error:     "Token expired",
		Token:     "reset-token-xyz",
		CSRFToken: "csrf-rp",
	}).Render(context.Background(), &buf)
	if err != nil {
		t.Fatalf("rendering ResetPassword component: %v", err)
	}
	requireContainsAll(t, buf.String(),
		"<!doctype html>",
		"<title>Reset Password</title>",
		`action="/oauth/reset-password"`,
		`name="csrf_token" value="csrf-rp"`,
		`name="token" value="reset-token-xyz"`,
		"Token expired",
	)
}

// TestPageTemplatesRenderEditProfile covers the edit-profile page, which has
// been migrated from html/template to a templ component (pkg/views). Instead
// of parsing an .html file by name, it renders the typed component directly.
func TestPageTemplatesRenderEditProfile(t *testing.T) {
	var buf bytes.Buffer
	err := views.EditProfile(views.EditProfileView{
		Success:    "Profile saved",
		GivenName:  "Ada",
		FamilyName: "Lovelace",
		CSRFToken:  "csrf-ep",
	}).Render(context.Background(), &buf)
	if err != nil {
		t.Fatalf("rendering EditProfile component: %v", err)
	}
	requireContainsAll(t, buf.String(),
		"<!doctype html>",
		"<title>Edit Profile</title>",
		"Profile saved",
		`value="Ada"`,
		`value="Lovelace"`,
		`name="csrf_token" value="csrf-ep"`,
	)
}

// TestPageTemplatesRenderChangeAvatar covers the change-avatar page, which
// has been migrated from html/template to a templ component (pkg/views).
// Instead of parsing an .html file by name, it renders the typed component
// directly. It also verifies the onchange="previewImage(this)" handler and
// the preview-container/preview-image element IDs that the inline script
// (rendered via Layout's scripts slot) references.
func TestPageTemplatesRenderChangeAvatar(t *testing.T) {
	var buf bytes.Buffer
	err := views.ChangeAvatar(views.ChangeAvatarView{
		Success:   "Avatar updated",
		AvatarURL: "https://example.com/avatar.png",
		CSRFToken: "csrf-ca",
	}).Render(context.Background(), &buf)
	if err != nil {
		t.Fatalf("rendering ChangeAvatar component: %v", err)
	}
	html := buf.String()
	requireContainsAll(t, html,
		"<!doctype html>",
		"<title>Change Avatar</title>",
		"Avatar updated",
		"https://example.com/avatar.png",
		`name="csrf_token" value="csrf-ca"`,
		`onchange="previewImage(this)"`,
		`id="preview-container"`,
		`id="preview-image"`,
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
		{"error.html", ErrorPageData{}},
		{"account-settings.html", AccountSettingsPageData{CSRFToken: "t"}},
		// change-password, change-username, change-email, edit-profile,
		// forgot-password, forgot-username, reset-password, register,
		// change-avatar, and success are templ components now (see their
		// dedicated TestPageTemplatesRender* tests).
		{"mfa.html", MFAPageData{CSRFToken: "t"}},
		{"mfa-setup.html", MFASetupPageData{CSRFToken: "t"}},
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
