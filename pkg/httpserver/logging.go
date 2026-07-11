package httpserver

import (
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

// sensitiveQueryParams lists query parameter names whose values must never be written
// to logs. Password-reset and email-verification links carry single-use secret tokens
// in a "token" query parameter (see password_reset.go's HandleForgotPasswordPost /
// email_verification.go's sendVerificationEmail), so it is redacted before any request
// is logged.
var sensitiveQueryParams = []string{"token"}

// requestLoggingMiddleware is a thin replacement for chi's middleware.Logger. chi's
// default logger logs the full request URI -- including the raw query string --
// verbatim, which would write single-use secret tokens straight into access logs (and
// from there into any log aggregation/shipping downstream). This middleware logs the
// same operationally useful fields (request ID, method, path, status, response size,
// duration) but redacts sensitive query parameter values first.
//
// It does not change the token-in-URL design itself (that would be a bigger change);
// it only keeps the token out of logs.
func requestLoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		defer func() {
			reqID := middleware.GetReqID(r.Context())
			log.Printf("[%s] %s %s -> %d %dB in %s",
				reqID, r.Method, redactedRequestPath(r.URL), ww.Status(), ww.BytesWritten(), time.Since(start))
		}()

		next.ServeHTTP(ww, r)
	})
}

// debugf logs a [DEBUG]-prefixed message when config.Debug is enabled (DEBUG=true), and
// is a no-op otherwise. Handlers use it for verbose flow/user-ID logging that is useful
// while debugging auth flows locally but too noisy to leave on unconditionally in
// production. Callers should not include the "[DEBUG] " prefix or a trailing newline in
// format; debugf adds the prefix itself (log.Printf already appends the newline).
func (s *Server) debugf(format string, args ...any) {
	if !s.config.Debug {
		return
	}
	log.Printf("[DEBUG] "+format, args...)
}

// redactedRequestPath returns the request path and query string with the value of any
// sensitive query parameter (see sensitiveQueryParams) replaced by "REDACTED". Requests
// with no sensitive parameters are returned unmodified (aside from re-serialization via
// url.Values.Encode, which reorders and re-escapes parameters but keeps the same query
// keys/values) so the log stays useful for debugging non-sensitive flows.
func redactedRequestPath(u *url.URL) string {
	if u.RawQuery == "" {
		return u.Path
	}

	q := u.Query()
	redacted := false
	for _, key := range sensitiveQueryParams {
		if q.Has(key) {
			q.Set(key, "REDACTED")
			redacted = true
		}
	}
	if !redacted {
		return u.Path + "?" + u.RawQuery
	}
	return u.Path + "?" + q.Encode()
}
