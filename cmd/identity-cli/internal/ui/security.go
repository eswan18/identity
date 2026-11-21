package ui

import (
	"crypto/subtle"
	"net/http"
	"strconv"
	"strings"
)

// protect is the panel's whole access control. The panel edits OAuth clients
// with the operator's database credentials, so a localhost server that
// anything else could drive would be a hole. It requires, on every request:
//
//   - a Host of 127.0.0.1:<port> or localhost:<port>, which defeats DNS
//     rebinding (a hostile name resolving to 127.0.0.1 still sends its own
//     Host);
//   - a path under /s/<pathSecret>/. Anything else is a 404. Browsers send
//     cookies to every port on a host, so the session cookie is scoped to this
//     path: another local server the operator visits is never asked for it,
//     so never receives the cookie;
//   - the session cookie, which only the first holder of the start URL's
//     token can obtain (the token is exchanged once; the cookie holds a
//     separate value). It is SameSite=Strict, so other sites' requests never
//     carry it;
//   - on POST, the csrf form field as well.
func (s *Server) protect(next http.Handler) http.Handler {
	port := strconv.Itoa(s.port)
	allowedHosts := map[string]bool{"127.0.0.1:" + port: true, "localhost:" + port: true}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")

		if !allowedHosts[r.Host] {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if !strings.HasPrefix(r.URL.Path, s.base()) {
			http.NotFound(w, r)
			return
		}

		signedIn := false
		if c, err := r.Cookie(s.cookieName()); err == nil && equal(c.Value, s.session) {
			signedIn = true
		}

		if tok := r.URL.Query().Get("token"); tok != "" {
			if !signedIn {
				if !s.useToken(tok) {
					http.Error(w, "this link has already been used or is wrong: restart identity-cli ui for a new one", http.StatusForbidden)
					return
				}
				http.SetCookie(w, &http.Cookie{
					Name:     s.cookieName(),
					Value:    s.session,
					Path:     s.base(),
					HttpOnly: true,
					SameSite: http.SameSiteStrictMode,
				})
			}
			http.Redirect(w, r, s.base(), http.StatusSeeOther)
			return
		}

		if !signedIn {
			http.Error(w, "not signed in: open the URL identity-cli ui printed", http.StatusForbidden)
			return
		}

		if r.Method == http.MethodPost {
			if !equal(r.PostFormValue("csrf"), s.csrf) {
				http.Error(w, "missing or wrong form token: reload the page and try again", http.StatusForbidden)
				return
			}
		} else if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// useToken reports whether tok is the start token and has not been used,
// and marks it used.
func (s *Server) useToken(tok string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tokenUsed || !equal(tok, s.token) {
		return false
	}
	s.tokenUsed = true
	return true
}

// cookieName includes the port, so two panels (staging and prod) on different
// ports in one browser keep separate sessions.
func (s *Server) cookieName() string { return "identity_ui_" + strconv.Itoa(s.port) }

func equal(a, b string) bool {
	return a != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
