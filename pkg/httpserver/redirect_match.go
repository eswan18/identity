package httpserver

import "github.com/eswan18/identity/pkg/redirecturi"

// redirectURIAllowed reports whether candidate is allowed by a client's
// registered redirect URIs.
//
// The rules live in pkg/redirecturi, which identity-cli's registration-time
// validation shares, so the request path and the CLI cannot disagree about what
// a well-formed wildcard entry is. In particular, the breadth guard on how wide
// a wildcard may be is enforced here on every authorize/consent request, not
// only when an operator registers the client -- a too-broad entry that reached
// the database by any other route is refused rather than honoured.
func redirectURIAllowed(registered []string, candidate string) bool {
	return redirecturi.Allowed(registered, candidate)
}
