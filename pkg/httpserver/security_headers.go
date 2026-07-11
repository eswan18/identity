package httpserver

import "net/http"

// securityHeadersMiddleware sets baseline security headers on every response. This
// matters most for the login and consent pages: an IdP's consent screen is the
// classic clickjacking target (an attacker frames it in an invisible iframe and
// tricks an already-authenticated user into approving a malicious client's consent
// request), so framing is disabled outright.
//
// secure gates Strict-Transport-Security: it must only be sent when the service is
// actually reached over HTTPS (see isSecureContext in server.go), because HSTS tells
// the browser to refuse plain-HTTP connections to this host for the given duration --
// sending it during local HTTP development would lock developers out of
// http://localhost.
func securityHeadersMiddleware(secure bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()

			// Belt-and-suspenders against clickjacking: X-Frame-Options for older
			// browsers that don't understand CSP, frame-ancestors (the modern
			// replacement) for the rest.
			h.Set("X-Frame-Options", "DENY")

			// frame-ancestors 'none' is the only directive in this CSP. The
			// server-rendered templates include inline <script> blocks and inline
			// event handlers (see templates/change-avatar.html,
			// templates/register.html) with no nonce/hash scheme in place, so adding
			// a script-src/style-src restriction today would either break those
			// pages or require 'unsafe-inline' -- which provides little real
			// protection anyway. Tightening the CSP further (nonces on the inline
			// scripts, then a strict script-src) is a good follow-up, not bundled
			// into this change.
			h.Set("Content-Security-Policy", "frame-ancestors 'none'")

			// Prevents browsers from MIME-sniffing responses away from the
			// declared Content-Type (e.g. treating an upload as executable HTML/JS).
			h.Set("X-Content-Type-Options", "nosniff")

			// no-referrer avoids leaking this origin's URLs -- including
			// password-reset and email-verification links that carry single-use
			// tokens in the query string -- via the Referer header when a page
			// links out to a third party.
			h.Set("Referrer-Policy", "no-referrer")

			if secure {
				// 2 years, apply to subdomains. Only sent over HTTPS/behind TLS;
				// see the `secure` parameter doc above.
				h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			}

			next.ServeHTTP(w, r)
		})
	}
}
