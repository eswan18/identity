package ui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/eswan18/identity/cmd/identity-cli/internal"
	"github.com/stretchr/testify/require"
)

func newTestServer(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	s, err := New(nil, internal.Target{Name: "staging", Source: "test", URL: "postgres://h.example/db"}, 8765)
	require.NoError(t, err)
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	return s, s.protect(ok)
}

func do(h http.Handler, method, target, host string, cookie *http.Cookie, form url.Values) *httptest.ResponseRecorder {
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequest(method, target, body)
	req.Host = host
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// startPath is StartURL without the scheme and host.
func startPath(t *testing.T, s *Server) string {
	t.Helper()
	u, err := url.Parse(s.StartURL())
	require.NoError(t, err)
	return u.RequestURI()
}

// login exchanges the start token for the session cookie.
func login(t *testing.T, s *Server, h http.Handler) *http.Cookie {
	t.Helper()
	rec := do(h, "GET", startPath(t, s), "127.0.0.1:8765", nil, nil)
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Equal(t, s.base(), rec.Header().Get("Location"))
	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	return cookies[0]
}

func TestUISecurityTokenLoginSetsStrictCookie(t *testing.T) {
	s, h := newTestServer(t)
	c := login(t, s, h)
	require.Equal(t, "identity_ui_8765", c.Name)
	require.True(t, c.HttpOnly)
	require.Equal(t, http.SameSiteStrictMode, c.SameSite)
	require.Equal(t, http.StatusOK, do(h, "GET", s.base()+"clients", "127.0.0.1:8765", c, nil).Code)
}

// Browsers send cookies to every port on a host, so the cookie must be
// scoped to a path no other local server will be asked for, and must not be
// the start token.
func TestUISecurityCookieScopedToSecretPath(t *testing.T) {
	s, h := newTestServer(t)
	c := login(t, s, h)
	require.Equal(t, s.base(), c.Path)
	require.True(t, strings.HasPrefix(c.Path, "/s/"))
	require.GreaterOrEqual(t, len(c.Path), len("/s/")+40, "the path carries a secret")
	require.NotEqual(t, s.token, c.Value, "the cookie is not the start token")
}

func TestUISecurityOutsideSecretPathNotFound(t *testing.T) {
	s, h := newTestServer(t)
	c := login(t, s, h)
	require.Equal(t, http.StatusNotFound, do(h, "GET", "/clients", "127.0.0.1:8765", c, nil).Code)
	require.Equal(t, http.StatusNotFound, do(h, "GET", "/s/wrong/clients", "127.0.0.1:8765", c, nil).Code)
	require.Equal(t, http.StatusNotFound, do(h, "GET", "/?token="+url.QueryEscape(s.token), "127.0.0.1:8765", nil, nil).Code,
		"the token alone, without the secret path, gets nothing")
}

func TestUISecurityStartTokenWorksOnce(t *testing.T) {
	s, h := newTestServer(t)
	c := login(t, s, h)
	rec := do(h, "GET", startPath(t, s), "127.0.0.1:8765", nil, nil)
	require.Equal(t, http.StatusForbidden, rec.Code, "a second exchange without the cookie is refused")
	require.Empty(t, rec.Result().Cookies())
	rec = do(h, "GET", startPath(t, s), "127.0.0.1:8765", c, nil)
	require.Equal(t, http.StatusSeeOther, rec.Code, "reopening the start URL in the signed-in browser just goes in")
	require.Empty(t, rec.Result().Cookies())
}

func TestUISecurityNoCookieForbidden(t *testing.T) {
	s, h := newTestServer(t)
	require.Equal(t, http.StatusForbidden, do(h, "GET", s.base()+"clients", "127.0.0.1:8765", nil, nil).Code)
}

func TestUISecurityWrongTokenForbidden(t *testing.T) {
	s, h := newTestServer(t)
	rec := do(h, "GET", s.base()+"?token=nope", "127.0.0.1:8765", nil, nil)
	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Empty(t, rec.Result().Cookies())
}

func TestUISecurityForeignHostForbidden(t *testing.T) {
	s, h := newTestServer(t)
	c := login(t, s, h)
	require.Equal(t, http.StatusForbidden, do(h, "GET", s.base()+"clients", "evil.example:8765", c, nil).Code)
	require.Equal(t, http.StatusForbidden, do(h, "GET", startPath(t, s), "evil.example:8765", nil, nil).Code)
}

func TestUISecurityLocalHostsAccepted(t *testing.T) {
	s, h := newTestServer(t)
	c := login(t, s, h)
	for _, host := range []string{"localhost:8765", "127.0.0.1:8765"} {
		require.Equal(t, http.StatusOK, do(h, "GET", s.base()+"clients", host, c, nil).Code, host)
	}
	require.Equal(t, http.StatusForbidden, do(h, "GET", s.base()+"clients", "localhost:9999", c, nil).Code, "another port")
}

func TestUISecurityPostNeedsCSRF(t *testing.T) {
	s, h := newTestServer(t)
	c := login(t, s, h)
	target := s.base() + "clients/new"
	require.Equal(t, http.StatusForbidden,
		do(h, "POST", target, "127.0.0.1:8765", c, url.Values{"name": {"x"}}).Code, "missing csrf")
	require.Equal(t, http.StatusForbidden,
		do(h, "POST", target, "127.0.0.1:8765", c, url.Values{"csrf": {"wrong"}}).Code, "wrong csrf")
	require.Equal(t, http.StatusOK,
		do(h, "POST", target, "127.0.0.1:8765", c, url.Values{"csrf": {s.csrf}}).Code)
	require.Equal(t, http.StatusForbidden,
		do(h, "POST", target, "127.0.0.1:8765", nil, url.Values{"csrf": {s.csrf}}).Code, "csrf without cookie")
}

func TestUISecurityStartURL(t *testing.T) {
	s, _ := newTestServer(t)
	require.Equal(t, "http://127.0.0.1:8765"+s.base()+"?token="+url.QueryEscape(s.token), s.StartURL())
	require.NotEqual(t, s.token, s.csrf)
	require.GreaterOrEqual(t, len(s.token), 40)
}

func TestUINewRefusesPortZero(t *testing.T) {
	_, err := New(nil, internal.Target{Name: "staging"}, 0)
	require.Error(t, err, "the allowed Host and the start URL need the real port")
}
