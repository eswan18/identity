package httpserver

import (
	"net/http"
	"net/url"
)

// Authorization responses: the redirects that hand the outcome of an
// authorization request back to the client, with a code (RFC 6749 §4.1.2) or
// an error (§4.1.2.1). Every one of them goes through respondToClient, which
// adds iss.
//
// iss is identity's issuer identifier (RFC 9207 §2, REQUIRED by OAuth 2.1).
// A client that talks to several authorization servers -- Claude, for one --
// checks it against the issuer it sent the user to, so an attacker cannot get
// it to redeem a code from one server at another (a mix-up attack). The
// discovery document advertises authorization_response_iss_parameter_supported,
// and a client that has seen that flag rejects any response without iss. So a
// single redirect that skipped this helper would not merely lack a defense; it
// would break that client outright, which is why there is one helper and the
// handlers do not build these URLs themselves.
//
// Errors identity shows on its own page instead -- an unknown client_id, a
// redirect_uri not registered for it -- are not authorization responses and do
// not carry iss: RFC 6749 §4.1.2.1 forbids redirecting those at all.

// respondWithCode sends the client the authorization code it asked for.
func (s *Server) respondWithCode(w http.ResponseWriter, r *http.Request, p authorizeParams, code string) {
	s.respondToClient(w, r, p, url.Values{"code": {code}})
}

// respondWithError sends the client an authorization error response.
func (s *Server) respondWithError(w http.ResponseWriter, r *http.Request, p authorizeParams, errorCode, description string) {
	s.respondToClient(w, r, p, url.Values{
		"error":             {errorCode},
		"error_description": {description},
	})
}

// respondToClient redirects the user agent to p.RedirectURI with params, the
// client's state, and iss.
//
// Only call it once p's client_id and redirect_uri have been validated
// together (validateOAuthClientRedirect): redirecting to an unvalidated
// redirect_uri is an open redirect. state is echoed only when the client sent
// one (RFC 6749 §4.1.2). Parameters already in the registered redirect URI's
// query are kept.
func (s *Server) respondToClient(w http.ResponseWriter, r *http.Request, p authorizeParams, params url.Values) {
	redirectURL, err := url.Parse(p.RedirectURI)
	if err != nil {
		http.Error(w, "Invalid redirect URI", http.StatusBadRequest)
		return
	}
	q := redirectURL.Query()
	for k, vs := range params {
		q[k] = vs
	}
	if p.State != "" {
		q.Set("state", p.State)
	}
	q.Set("iss", s.config.JWTIssuer)
	redirectURL.RawQuery = q.Encode()
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}
