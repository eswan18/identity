package views

import "net/url"

// AuthorizeQueryField names the one value that carries an OAuth authorization
// request through the pages between /oauth/authorize and the code: login, MFA,
// registration and consent. Its value is the original /oauth/authorize
// request's query string, verbatim. Each page holds it in a hidden input (or,
// on links and redirects between pages, a query parameter of this name), and
// the handler at the end of the chain re-parses and re-validates it.
//
// It replaced one hidden input per authorize parameter. Those had to be added
// to every page and handler by hand, and a parameter missed anywhere was
// silently dropped -- registration lost nonce that way. A parameter the
// authorize endpoint learns to read now survives every page with no change
// here.
const AuthorizeQueryField = "authorize_query"

// flowURL is path with the authorization request attached, for links between
// the sign-in and sign-up pages, or path alone outside an OAuth flow. The
// request is query-encoded as one value, so nothing in it can add parameters
// to the link or break out of it.
func flowURL(path, authorizeQuery string) string {
	if authorizeQuery == "" {
		return path
	}
	return path + "?" + url.Values{AuthorizeQueryField: {authorizeQuery}}.Encode()
}
