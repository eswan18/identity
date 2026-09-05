package internal

import (
	"strings"

	"github.com/eswan18/identity/pkg/redirecturi"
)

// ValidateRedirectURIs rejects malformed wildcard redirect entries before they
// reach the database. Only entries containing "*" are validated -- non-wildcard
// URIs (including localhost/http dev entries) pass through untouched, matching
// the server's runtime behavior where exact-match entries are compared
// byte-for-byte.
//
// The rules themselves live in pkg/redirecturi and are shared with the
// authorize/consent request path (see redirectURIAllowed in
// pkg/httpserver/redirect_match.go), so the two cannot drift. This function is
// a convenience that fails the operator's command early with a clear message;
// it is not the security boundary, because the CLI is not the only way a row
// can reach oauth_clients.redirect_uris. The request path enforces the same
// rules independently.
func ValidateRedirectURIs(uris []string) error {
	for _, raw := range uris {
		if !strings.Contains(raw, "*") {
			continue
		}
		if err := redirecturi.ValidateWildcardPattern(raw); err != nil {
			return err
		}
	}
	return nil
}
