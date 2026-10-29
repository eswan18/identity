package httpserver

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/eswan18/identity/pkg/views"
)

// The page a signed-out visitor asked for, carried through sign-in (login and,
// when it applies, MFA) so they land back on it afterwards instead of on
// account settings. It travels as views.ReturnToField: a query parameter on
// the redirect to /oauth/login and to /oauth/mfa, and a hidden input on their
// forms.
//
// Like the authorization request, it is untrusted: the user can edit it, and
// anyone can link to /oauth/login?return_to=... . So it is only ever read
// through safeReturnPath, which accepts nothing but a path on this server, and
// a value it refuses is dropped (the user goes to account settings), never
// followed. An OAuth flow in progress always wins over it; see
// redirectAfterAuth.

// defaultAfterSignIn is where a direct sign-in goes when no page was asked for.
const defaultAfterSignIn = "/oauth/account-settings"

// safeReturnPath returns raw if it is a same-origin path to send a browser to
// (a path, optionally with a query, on this server), or "" if it is anything
// else. In particular it refuses:
//   - absolute URLs (https://evil.example/) and scheme-relative ones
//     (//evil.example/), which browsers resolve against another host;
//   - backslashes anywhere, because browsers treat "/\evil.example" as
//     "//evil.example";
//   - control characters and whitespace, which browsers strip, so
//     "/\t/evil.example" would become "//evil.example";
//   - fragments and anything url.Parse reads as having a scheme, host or
//     user.
func safeReturnPath(raw string) string {
	if raw == "" || len(raw) > 2048 {
		return ""
	}
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return ""
	}
	for _, c := range raw {
		if c == '\\' || c <= ' ' || c == 0x7f {
			return ""
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" || u.Fragment != "" {
		return ""
	}
	// After percent-decoding, the path must still not start with "//" or
	// contain a backslash: some servers and proxies decode before routing.
	if strings.HasPrefix(u.Path, "//") || strings.Contains(u.Path, `\`) {
		return ""
	}
	return raw
}

// carriedReturnTo reads the page to return to after sign-in from the
// request's form or query string, or "" if there is none or it is not a safe
// path (see safeReturnPath).
func carriedReturnTo(r *http.Request) string {
	return safeReturnPath(r.FormValue(views.ReturnToField))
}

// withReturnTo is target (a path that may already have a query) with returnTo
// added as views.ReturnToField, or target unchanged when returnTo is empty.
func withReturnTo(target, returnTo string) string {
	if returnTo == "" {
		return target
	}
	sep := "?"
	if strings.Contains(target, "?") {
		sep = "&"
	}
	return target + sep + url.Values{views.ReturnToField: {returnTo}}.Encode()
}

// loginURLReturningTo is the login page for a signed-out visit to r: it
// carries r's path and query as the page to come back to, for a GET (a page
// the user can be sent back to). The default destination is not carried, and
// nor is anything else, so the login URL stays plain.
func loginURLReturningTo(r *http.Request) string {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return "/oauth/login"
	}
	returnTo := safeReturnPath(r.URL.RequestURI())
	if returnTo == defaultAfterSignIn {
		returnTo = ""
	}
	return withReturnTo("/oauth/login", returnTo)
}
