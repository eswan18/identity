package httpserver

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
)

// csrfCookieName is the name of the double-submit CSRF cookie and the matching
// hidden form field.
const csrfCookieName = "csrf_token"

// csrfFormField is the form field (and hidden <input> name) that carries the CSRF
// token back on state-changing submits. It intentionally matches the cookie name.
const csrfFormField = "csrf_token"

// csrfTokenBytes is the number of random bytes in a CSRF token before encoding.
const csrfTokenBytes = 32

// generateCSRFToken returns a cryptographically random, URL-safe token string.
func generateCSRFToken() (string, error) {
	b := make([]byte, csrfTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// setCSRFCookie writes the csrf_token cookie. It mirrors the session cookie's flags:
// HttpOnly (the server renders the hidden field, so JS never needs to read it),
// SameSite=Lax, and Secure gated on isSecureContext (see server.go) so it is only
// marked Secure when the service is actually reached over HTTPS. It is a session
// cookie (no Max-Age/Expires) so the same token persists across the multi-step
// browser flows (e.g. login -> mfa) for the life of the browser session.
func (s *Server) setCSRFCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.isSecureContext(),
		SameSite: http.SameSiteLaxMode,
	})
}

// ensureCSRFToken returns the CSRF token for this request, creating and setting the
// csrf_token cookie if the request does not already carry a valid one. GET handlers
// that render a protected form call this and embed the returned value as a hidden
// field so the double-submit check can succeed on the subsequent POST.
//
// Because the cookie has Path=/ and is a session cookie, a token minted while
// rendering one form page (e.g. /oauth/login) remains valid for a later form on a
// different page in the same session (e.g. /oauth/mfa, /oauth/account-settings).
func (s *Server) ensureCSRFToken(w http.ResponseWriter, r *http.Request) string {
	if cookie, err := r.Cookie(csrfCookieName); err == nil && cookie.Value != "" {
		return cookie.Value
	}
	token, err := generateCSRFToken()
	if err != nil {
		// Extremely unlikely (crypto/rand failure). Return empty; the form will then
		// carry no token and the middleware will reject the eventual POST with 403,
		// which is the safe failure mode.
		return ""
	}
	s.setCSRFCookie(w, token)
	return token
}

// csrfMiddleware enforces the double-submit-cookie CSRF check on state-changing
// requests to the browser, session-cookie form routes it wraps. Safe methods
// (GET/HEAD/OPTIONS) are never checked. For every other method the request must
// carry a csrf_token cookie and a csrf_token form value that are both present and
// equal (compared in constant time). Failure is a 403.
//
// This middleware is applied ONLY to the browser form route group. The OAuth2/OIDC
// machine endpoints (/oauth/token, /oauth/refresh, /oauth/introspect, /oauth/revoke)
// and the admin API authenticate with Authorization headers / client credentials and
// have no browser form, so they are deliberately outside this group and never see it.
func (s *Server) csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}

		cookie, err := r.Cookie(csrfCookieName)
		if err != nil || cookie.Value == "" {
			s.renderError(w, http.StatusForbidden, "Invalid Request",
				"Your session could not be verified (missing CSRF token). Please reload the page and try again.", "")
			return
		}

		formToken := r.FormValue(csrfFormField)
		if formToken == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(formToken)) != 1 {
			s.renderError(w, http.StatusForbidden, "Invalid Request",
				"Your session could not be verified (CSRF token mismatch). Please reload the page and try again.", "")
			return
		}

		next.ServeHTTP(w, r)
	})
}
