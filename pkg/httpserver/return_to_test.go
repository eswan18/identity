package httpserver

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestSafeReturnPath(t *testing.T) {
	accepted := []string{
		"/oauth/connected-apps",
		"/oauth/account-settings",
		"/oauth/change-email?x=1&y=2",
		"/",
		"/oauth/a%2Fb",
	}
	for _, p := range accepted {
		if got := safeReturnPath(p); got != p {
			t.Errorf("safeReturnPath(%q) = %q, want it accepted unchanged", p, got)
		}
	}

	refused := []string{
		"",
		"https://evil.example/",
		"http://evil.example",
		"//evil.example/path",
		"///evil.example",
		`/\evil.example`,
		`\\evil.example`,
		"/\t/evil.example",
		"/\n/evil.example",
		"/ /evil.example",
		"/%2F/evil.example", // decodes to "//evil.example"
		"/%5Cevil.example",  // decodes to "/\evil.example"
		"javascript:alert(1)",
		"oauth/connected-apps",
		"/oauth/connected-apps#frag",
		"/" + strings.Repeat("a", 3000),
	}
	for _, p := range refused {
		if got := safeReturnPath(p); got != "" {
			t.Errorf("safeReturnPath(%q) = %q, want it refused", p, got)
		}
	}
}

func TestLoginURLReturningTo(t *testing.T) {
	cases := []struct {
		method, target, want string
	}{
		{http.MethodGet, "/oauth/connected-apps", "/oauth/login?return_to=%2Foauth%2Fconnected-apps"},
		{http.MethodGet, "/oauth/change-email?a=b", "/oauth/login?return_to=%2Foauth%2Fchange-email%3Fa%3Db"},
		// Where sign-in goes anyway: nothing to carry.
		{http.MethodGet, "/oauth/account-settings", "/oauth/login"},
		// A POST cannot be replayed by a redirect: nothing to carry.
		{http.MethodPost, "/oauth/connected-apps/disconnect", "/oauth/login"},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, c.target, nil)
		if got := loginURLReturningTo(req); got != c.want {
			t.Errorf("%s %s: loginURLReturningTo = %q, want %q", c.method, c.target, got, c.want)
		}
	}
}

func TestWithReturnTo(t *testing.T) {
	if got := withReturnTo("/oauth/mfa?pending=abc", "/oauth/connected-apps"); got != "/oauth/mfa?pending=abc&return_to=%2Foauth%2Fconnected-apps" {
		t.Errorf("got %q", got)
	}
	if got := withReturnTo("/oauth/login", ""); got != "/oauth/login" {
		t.Errorf("empty return_to should leave the URL alone, got %q", got)
	}
}

// The login page carries a safe return_to in a hidden input and drops an
// unsafe one entirely.
func TestHandleLoginGet_CarriesOnlySafeReturnTo(t *testing.T) {
	s := newHermeticTestServer(t)

	rec := httptest.NewRecorder()
	s.HandleLoginGet(rec, httptest.NewRequest(http.MethodGet, "/oauth/login?return_to="+url.QueryEscape("/oauth/connected-apps"), nil))
	if !strings.Contains(rec.Body.String(), `name="return_to" value="/oauth/connected-apps"`) {
		t.Errorf("login page should carry return_to; body:\n%s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	s.HandleLoginGet(rec, httptest.NewRequest(http.MethodGet, "/oauth/login?return_to="+url.QueryEscape("//evil.example/"), nil))
	if strings.Contains(rec.Body.String(), `name="return_to"`) || strings.Contains(rec.Body.String(), "evil.example") {
		t.Errorf("login page must drop an unsafe return_to; body:\n%s", rec.Body.String())
	}
}

// directSignInDestination follows a safe return_to and otherwise goes to
// account settings.
func TestDirectSignInDestination(t *testing.T) {
	cases := map[string]string{
		"/oauth/connected-apps": "/oauth/connected-apps",
		"https://evil.example/": defaultAfterSignIn,
		"//evil.example":        defaultAfterSignIn,
		"":                      defaultAfterSignIn,
	}
	for returnTo, want := range cases {
		form := url.Values{"return_to": {returnTo}}
		req := httptest.NewRequest(http.MethodPost, "/oauth/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if got := directSignInDestination(req); got != want {
			t.Errorf("return_to %q: got %q, want %q", returnTo, got, want)
		}
	}
}
