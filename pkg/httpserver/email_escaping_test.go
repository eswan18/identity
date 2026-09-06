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

// urlBuilders are the two builders that interpolate a URL into an href
// attribute. Both URLs are built from config.JWTIssuer plus a hex token, so
// neither can currently carry markup; these tests pin the escaping so that
// stays true if either URL ever gains a caller-influenced component.
var urlBuilders = map[string]func(string) string{
	"buildPasswordResetEmailHTML": buildPasswordResetEmailHTML,
	"buildVerificationEmailHTML": func(u string) string {
		return buildVerificationEmailHTML(benignUsername, u)
	},
}

func TestEmailHTMLBuildersEscapeURL(t *testing.T) {
	const payload = `https://identity.example.com/oauth/x?token=y"><script>alert(1)</script>`
	const benignURL = "https://identity.example.com/oauth/x?token=abc"

	for name, build := range urlBuilders {
		t.Run(name, func(t *testing.T) {
			body := build(payload)

			if strings.Contains(body, payload) {
				t.Errorf("%s: body contains the payload verbatim:\n%s", name, body)
			}
			if got, baseline := countTags(body), countTags(build(benignURL)); got != baseline {
				t.Errorf("%s: body has %d tags, baseline has %d — the URL injected %d tag(s):\n%s",
					name, got, baseline, got-baseline, body)
			}
			if !strings.Contains(body, "&lt;script&gt;") {
				t.Errorf("%s: body does not contain the escaped URL; got:\n%s", name, body)
			}
		})
	}
}

// TestEmailHTMLBuildersEscapeQuotes is the assertion tag counting cannot make.
//
// Both URLs land inside href="%s". A partial escaper that handled only < and >
// would satisfy every check above -- no new tags, payload absent verbatim -- while
// still allowing an attribute breakout such as
//
//	href="https://ok/" onmouseover="alert(1)"
//
// so the quote itself has to be pinned separately. The payload here deliberately
// contains no angle brackets, so this test fails for exactly one reason.
func TestEmailHTMLBuildersEscapeQuotes(t *testing.T) {
	const payload = `https://identity.example.com/x?t=1" onmouseover="alert(1)`

	for name, build := range urlBuilders {
		t.Run(name, func(t *testing.T) {
			body := build(payload)

			if strings.Contains(body, `" onmouseover="`) {
				t.Errorf("%s: quote survived unescaped — attribute breakout is possible:\n%s", name, body)
			}
			if !strings.Contains(body, "&#34;") {
				t.Errorf("%s: body has no escaped quote, so quotes are not being escaped:\n%s", name, body)
			}
		})
	}

	// The same for a username, which reaches element text rather than an
	// attribute today -- but nothing structurally prevents a future template
	// from placing it in an attribute, and escaping is what makes that safe.
	body := buildUsernameReminderEmailHTML(`bob" onmouseover="alert(1)`)
	if strings.Contains(body, `" onmouseover="`) {
		t.Errorf("buildUsernameReminderEmailHTML: quote survived unescaped:\n%s", body)
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
