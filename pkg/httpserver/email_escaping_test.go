package httpserver

import (
	"strings"
	"testing"
)

// injectedUsername is a payload of the shape an attacker would have used before
// auth.ValidateUsername existed: it closes the surrounding <p>, adds a link of
// its own, and reopens a <p> so the rest of the message still renders normally.
const injectedUsername = `</p><a href="https://evil.example/reset">Reset your password</a><p style="display:none">`

// benignUsername is a valid username filling the same slot as injectedUsername,
// used as the baseline in the tag-count comparison below.
const benignUsername = "testuser"

// countTags reports how many HTML tags a body contains.
//
// Comparing this between a benign and a malicious username is the assertion
// that actually means something. Scanning the whole document for fragments like
// "<a href=" would false-positive on the templates' own markup -- the
// verification email legitimately contains a "Verify Email" anchor and several
// <p> tags. What matters is that interpolating a payload adds no tags of its own.
func countTags(body string) int {
	return strings.Count(body, "<")
}

// TestEmailHTMLBuildersEscapeUsername is the regression test for the injection
// half of the finding. auth.ValidateUsername now prevents such a username from
// being set in the first place, but accounts created before that rule existed
// can still hold one, so the sinks themselves must escape. These builders are
// the sinks.
func TestEmailHTMLBuildersEscapeUsername(t *testing.T) {
	builders := map[string]func(string) string{
		"buildVerificationEmailHTML": func(u string) string {
			return buildVerificationEmailHTML(u, "https://identity.example.com/oauth/verify-email?token=abc")
		},
		"buildUsernameReminderEmailHTML": buildUsernameReminderEmailHTML,
	}

	for name, build := range builders {
		t.Run(name, func(t *testing.T) {
			body := build(injectedUsername)

			// The payload must not survive verbatim anywhere in the body.
			if strings.Contains(body, injectedUsername) {
				t.Errorf("%s: body contains the payload verbatim — it was rendered as markup:\n%s", name, body)
			}

			// And it must not have contributed any tags of its own.
			baseline := countTags(build(benignUsername))
			if got := countTags(body); got != baseline {
				t.Errorf("%s: body has %d tags, baseline has %d — the payload injected %d tag(s):\n%s",
					name, got, baseline, got-baseline, body)
			}

			// Confirm the username is still present in escaped form, so we know it
			// was rendered rather than silently dropped.
			if !strings.Contains(body, "&lt;a href=") {
				t.Errorf("%s: body does not contain the escaped username; got:\n%s", name, body)
			}
		})
	}
}

// TestPasswordResetEmailHTMLEscapesURL covers the other interpolated value. The
// reset URL is built from config.JWTIssuer plus a hex token so it cannot
// currently carry markup; this pins the escaping so that stays true if the URL
// ever gains a caller-influenced component.
func TestPasswordResetEmailHTMLEscapesURL(t *testing.T) {
	const payload = `https://identity.example.com/oauth/reset-password?token=x"><script>alert(1)</script>`

	body := buildPasswordResetEmailHTML(payload)
	baseline := countTags(buildPasswordResetEmailHTML("https://identity.example.com/oauth/reset-password?token=abc"))

	if strings.Contains(body, payload) {
		t.Errorf("body contains the payload verbatim — the URL escaped its attribute:\n%s", body)
	}
	if got := countTags(body); got != baseline {
		t.Errorf("body has %d tags, baseline has %d — the URL injected %d tag(s):\n%s",
			got, baseline, got-baseline, body)
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("body does not contain the escaped URL; got:\n%s", body)
	}
}

// TestEmailTextBuildersDoNotEscape documents the deliberate asymmetry: the
// plain-text parts carry the literal value. Escaping there would render
// "&amp;" to the reader, and there is no markup context to escape for.
func TestEmailTextBuildersDoNotEscape(t *testing.T) {
	const username = "a&b<c"

	if got := buildUsernameReminderEmailText(username); !strings.Contains(got, username) {
		t.Errorf("buildUsernameReminderEmailText should carry the literal username %q, got:\n%s", username, got)
	}
	if got := buildVerificationEmailText(username, "https://example.com/v?a=1&b=2"); !strings.Contains(got, username) {
		t.Errorf("buildVerificationEmailText should carry the literal username %q, got:\n%s", username, got)
	}

	const url = "https://example.com/reset?token=a&b=2"
	if got := buildPasswordResetEmailText(url); !strings.Contains(got, url) {
		t.Errorf("buildPasswordResetEmailText should carry the literal URL %q, got:\n%s", url, got)
	}
}
