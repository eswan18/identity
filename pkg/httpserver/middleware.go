package httpserver

import (
	"context"
	"net/http"

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
