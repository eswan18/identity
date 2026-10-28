package httpserver

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/eswan18/identity/pkg/views"
)

// authorizeRequest is an OAuth authorization request carried through the
// pages between /oauth/authorize and the code: login, MFA, registration and
// consent. It is the original /oauth/authorize request's query string,
// verbatim -- not the parameters identity happened to know about when it was
// written.
//
// That is the point. When each page carried the parameters field by field, a
// parameter had to be added to every page, handler and the pending-MFA table,
// and anywhere it was missed it was silently dropped (registration lost nonce
// that way). Carried whole, a parameter /oauth/authorize learns to read needs
// no plumbing at all: it arrives back at authorize, or at consent, exactly as
// the client sent it.
//
// It is untrusted. It sits in a hidden form field and a query parameter the
// user can edit, so nothing here validates it and nothing reads it as a
// decision. Every step that acts on it re-parses it with params and sends the
// result through validateOAuthClientRedirect and checkCodeIssuance, as
// /oauth/authorize does for a request that arrives directly. Tampering with it
// can produce only what sending a different authorize request could.
type authorizeRequest string

// carriedAuthorizeRequest reads the authorization request a page carried
// (views.AuthorizeQueryField) from the request's form or query string. It is
// empty outside an OAuth flow.
func carriedAuthorizeRequest(r *http.Request) authorizeRequest {
	return authorizeRequest(r.FormValue(views.AuthorizeQueryField))
}

// params parses the request. A malformed pair is skipped rather than failing
// the whole request, which is what r.URL.Query() does for the same query when
// it arrives at /oauth/authorize directly, so both read it the same way.
func (a authorizeRequest) params() authorizeParams {
	q, _ := url.ParseQuery(string(a))
	return parseAuthorizeParams(q)
}

// inFlow reports whether the request belongs to an OAuth client's flow, as
// opposed to a direct sign-in to identity's own account pages.
func (a authorizeRequest) inFlow() bool {
	return a.params().ClientID != ""
}

// authorizeURL is /oauth/authorize with the original request, for resuming the
// flow once whatever interrupted it (sign-in, MFA) is done. The query is the
// one the client sent, byte for byte; the path is fixed, so nothing in the
// query can send the user anywhere but identity's own authorize endpoint.
func (a authorizeRequest) authorizeURL() string {
	return "/oauth/authorize?" + string(a)
}

// pageURL is path carrying the request as views.AuthorizeQueryField, plus any
// extra parameters for that page (a login notice, say). Outside an OAuth flow
// it carries only the extras.
func (a authorizeRequest) pageURL(path string, extra url.Values) string {
	q := url.Values{}
	for k, vs := range extra {
		q[k] = vs
	}
	if a != "" {
		q.Set(views.AuthorizeQueryField, string(a))
	}
	if len(q) == 0 {
		return path
	}
	return path + "?" + q.Encode()
}

// loginURL is the login page carrying the request, with an optional notice
// for it (see HandleLoginGet), for example "error" = "account_deactivated".
func (a authorizeRequest) loginURL(extra url.Values) string {
	return a.pageURL("/oauth/login", extra)
}

// consentURL is the consent page carrying the request.
func (a authorizeRequest) consentURL() string {
	return a.pageURL("/oauth/consent", nil)
}

// authorizeParams are the parameters of an authorization request that
// identity reads. parseAuthorizeParams is the only place they are read from a
// query, so /oauth/authorize, the login page and consent cannot disagree about
// what a request asked for.
type authorizeParams struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               []string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
}

// parseAuthorizeParams reads an authorization request's parameters. scope
// defaults to "openid" when absent.
func parseAuthorizeParams(q url.Values) authorizeParams {
	scope := []string{"openid"}
	if s := q.Get("scope"); s != "" {
		scope = strings.Split(s, " ")
	}
	return authorizeParams{
		ResponseType:        q.Get("response_type"),
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		Scope:               scope,
		State:               q.Get("state"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
		Nonce:               q.Get("nonce"),
	}
}
