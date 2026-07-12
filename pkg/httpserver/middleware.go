package httpserver

import (
	"context"
	"net/http"

	"github.com/eswan18/identity/pkg/avatar"
	"github.com/eswan18/identity/pkg/db"
)

// userCtxKey is the unexported context key under which the authenticated user is
// stored by the requireUser middlewares. Using a distinct unexported type avoids
// collisions with any other context value.
type userCtxKey struct{}

// userFromContext returns the authenticated user previously stored in ctx by one
// of the requireUser middlewares. ok is false when no user is present (which,
// behind the middleware, should not happen).
func userFromContext(ctx context.Context) (db.AuthUser, bool) {
	user, ok := ctx.Value(userCtxKey{}).(db.AuthUser)
	return user, ok
}

// contextWithUser returns a copy of ctx carrying the given authenticated user.
func contextWithUser(ctx context.Context, user db.AuthUser) context.Context {
	return context.WithValue(ctx, userCtxKey{}, user)
}

// requireActiveUser is middleware that loads the active (non-deactivated) user
// from the session cookie using the same logic as getUserFromSession. On failure
// it performs the same redirect the account handlers previously did inline
// (302 Found to /oauth/login); on success it stores the user in the request
// context (retrievable via userFromContext) and calls next.
func (s *Server) requireActiveUser(next http.Handler) http.Handler {
	return s.requireUserWith(next, s.getUserFromSession)
}

// requireUser is middleware identical to requireActiveUser except it also accepts
// deactivated users (via getUserFromSessionIncludingInactive). It is used for the
// account-settings, deactivate-account, and reactivate-account routes, which must
// remain reachable for a user whose account is inactive.
func (s *Server) requireUser(next http.Handler) http.Handler {
	return s.requireUserWith(next, s.getUserFromSessionIncludingInactive)
}

// requireUserWith is the shared implementation for the requireUser middlewares.
// The lookup function selects which session helper (active-only vs including
// inactive) is used to resolve the user.
func (s *Server) requireUserWith(next http.Handler, lookup func(*http.Request) (db.AuthUser, error)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := lookup(r)
		if err != nil {
			http.Redirect(w, r, "/oauth/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r.WithContext(contextWithUser(r.Context(), user)))
	})
}

// maxAvatarUploadBytes bounds the raw HTTP request body of a change-avatar
// upload to avatar.MaxAvatarRequestBodySize BEFORE any form parsing occurs, and
// eagerly parses the multipart form so that bound is actually enforced at this
// point in the middleware chain rather than later.
//
// Why this has to run here, ahead of csrfMiddleware:
//
// POST /oauth/change-avatar sits behind csrfMiddleware (see routes.go), which
// calls r.FormValue(csrfFormField) to read the csrf_token field. Because this
// route's content type is multipart/form-data, that FormValue call triggers
// r.ParseMultipartForm(32<<20) internally (Go's default). The "maxMemory"
// argument to ParseMultipartForm is NOT an overall body-size limit - it only
// controls how much of the body is buffered in memory before the rest is
// spooled to a temporary file on disk. Without a cap on r.Body itself, a
// client can POST a multi-gigabyte body to this route and csrfMiddleware's
// implicit parse (or, previously, the handler's own ParseMultipartForm call)
// will read and spool the entire thing to disk before any size check - the
// handler's 5MB avatar.MaxAvatarSize check included - ever runs. That is the
// DoS this middleware closes.
//
// Wrapping r.Body in http.MaxBytesReader and forcing the parse here, ahead of
// csrfMiddleware in the chain (see the r.With(...) registration in
// routes.go), makes the limit bind on the very first parse of the body,
// whoever triggers it. If the body is within bounds, ParseMultipartForm
// succeeds and caches the result on the request (r.MultipartForm), so both
// csrfMiddleware's later FormValue call and the handler's own
// ParseMultipartForm call are cheap no-ops against the already-parsed form -
// including the csrf_token field, which parses normally since the bound
// leaves it comfortably room (see avatar.MaxAvatarRequestBodySize). If the
// body exceeds the limit, ParseMultipartForm returns an error and we respond
// immediately with 413, before the CSRF check or the handler ever run.
func (s *Server) maxAvatarUploadBytes(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, avatar.MaxAvatarRequestBodySize)
		if err := r.ParseMultipartForm(avatar.MaxAvatarRequestBodySize); err != nil {
			s.renderError(w, http.StatusRequestEntityTooLarge, "File Too Large",
				"The file you uploaded is too large. Maximum upload size is 5MB.", "")
			return
		}
		next.ServeHTTP(w, r)
	})
}
