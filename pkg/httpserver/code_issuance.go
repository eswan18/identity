package httpserver

import (
	"net/http"

	"github.com/eswan18/identity/pkg/db"
)

// Preconditions for issuing an authorization code.
//
// Two handlers mint authorization codes: HandleOauthAuthorize and
// HandleConsentPost. Anything that must be true before a code is issued belongs
// in checkCodeIssuance below, so that it holds for both by construction.
//
// This is not a hypothetical concern. validateAuthorizeParams already exists
// because these two drifted once: consent skipped the authorize checks
// entirely, and a direct POST to /oauth/consent could obtain a PKCE-less code
// with arbitrary scopes. That was fixed by extracting the parameter checks --
// but only the parameter checks. The session lookup, the user lookup and the
// is-active check stayed inline in HandleOauthAuthorize, and consent never grew
// the is-active one, so a deactivated user with a still-valid session on another
// device could drive consent directly and have a code redirected to the client.
// (It could not be redeemed -- generateTokens filters on is_active -- but the
// client received a code and a misleading server_error at exchange.)
//
// So: to add a precondition, add it to checkCodeIssuance and give it a denial
// kind. Do not add it to a handler. denyCodeIssuance's default branch refuses
// anything it does not recognise, so a new kind that a caller forgets to render
// fails closed rather than falling through to issuing a code.

// codeIssuanceDenialKind identifies why a code may not be issued. Each kind
// corresponds to a distinct response, since the two callers surface some of
// these differently (a browser navigation vs. a form POST).
type codeIssuanceDenialKind int

const (
	// denialUnspecified is the zero value, and is deliberately not a real
	// denial reason.
	//
	// It exists because the zero value is what a mistake produces: a
	// codeIssuanceDenial constructed without setting Kind, or a kind added to
	// this list later and not yet handled everywhere. If the zero value were a
	// real reason, that mistake would be rendered as whatever reason happened to
	// sit at iota 0 -- and when this file was first written that was
	// denialInvalidParams, the single branch that dereferences OAuthError, so
	// the zero value panicked rather than failing closed as the comment above
	// promised. Reserving iota 0 makes the accident land in denyCodeIssuance's
	// default branch, which is the whole point of having one.
	denialUnspecified codeIssuanceDenialKind = iota
	// denialInvalidParams: the request parameters are not acceptable for this
	// client. Carries the RFC 6749 error to hand back.
	denialInvalidParams
	// denialNoSession: no valid session cookie; the user must authenticate.
	denialNoSession
	// denialUserLookupFailed: the session is valid but the user could not be
	// loaded. Treated as a server error, never as permission to proceed.
	denialUserLookupFailed
	// denialUserInactive: the account is deactivated.
	denialUserInactive
)

// codeIssuanceDenial is the reason a code may not be issued.
type codeIssuanceDenial struct {
	Kind codeIssuanceDenialKind
	// OAuthError is set only when Kind is denialInvalidParams.
	OAuthError *oauthAuthorizeError
}

// codeIssuanceGrant is what a caller needs once every precondition holds.
type codeIssuanceGrant struct {
	Session Session
	User    db.AuthUser
}

// checkCodeIssuance reports whether this request may be issued an authorization
// code, for both code-minting paths.
//
// It returns exactly one of grant or denial. Callers must not proceed on a
// denial, and must not re-check these conditions themselves -- a check that
// lives in a handler is a check the other handler does not have.
//
// It must stay a PURE PREDICATE. It is not a hook for things that happen once
// per issued code, because it does not run once per issued code:
//
//   - A single successful flow calls it twice. /oauth/authorize checks, finds
//     no stored consent, and redirects to /oauth/consent, which checks again.
//   - It also runs on requests that mint nothing -- an unauthenticated caller,
//     a deactivated account, invalid parameters.
//
// So a rate limit, an audit record, a counter, or a single-use nonce does not
// belong here: it would be charged twice for one code and charged for requests
// that produced none. Those belong at the generateAuthorizationCode call sites,
// which really are one-per-code.
func (s *Server) checkCodeIssuance(
	r *http.Request,
	client db.OauthClient,
	responseType, codeChallenge, codeChallengeMethod string,
	scope []string,
) (*codeIssuanceGrant, *codeIssuanceDenial) {
	if authErr := validateAuthorizeParams(client, responseType, codeChallenge, codeChallengeMethod, scope); authErr != nil {
		return nil, &codeIssuanceDenial{Kind: denialInvalidParams, OAuthError: authErr}
	}

	session, err := s.getSessionFromCookie(r)
	if err != nil {
		return nil, &codeIssuanceDenial{Kind: denialNoSession}
	}

	// Deliberately the including-inactive lookup: a deactivated user must be
	// distinguished from a missing one so the two get different responses.
	user, err := s.datastore.Q.GetUserByIDIncludingInactive(r.Context(), session.UserID)
	if err != nil {
		return nil, &codeIssuanceDenial{Kind: denialUserLookupFailed}
	}
	if !user.IsActive {
		return nil, &codeIssuanceDenial{Kind: denialUserInactive}
	}

	return &codeIssuanceGrant{Session: session, User: user}, nil
}

// codeIssuanceRedirects is where a caller wants each class of denial to go.
// The two handlers differ here and only here: authorize is a browser navigation
// carrying the OAuth parameters in its query string, consent is a form POST that
// has to rebuild them.
type codeIssuanceRedirects struct {
	// ToClient hands an OAuth error back to the client's redirect_uri per RFC
	// 6749 §4.1.2.1. Only safe once client_id and redirect_uri are validated.
	ToClient func(errorCode, description string)
	// Unauthenticated is where to send a user with no valid session.
	Unauthenticated string
	// Deactivated is where to send a user whose account is deactivated.
	Deactivated string
}

// denyCodeIssuance writes the response for a denial.
//
// The default branch is load-bearing: a denial kind added later that a caller
// has not thought about is refused as a server error rather than silently
// treated as success.
func (s *Server) denyCodeIssuance(w http.ResponseWriter, r *http.Request, d *codeIssuanceDenial, to codeIssuanceRedirects) {
	switch {
	case d.Kind == denialInvalidParams && d.OAuthError != nil:
		to.ToClient(d.OAuthError.Code, d.OAuthError.Description)
	case d.Kind == denialNoSession:
		http.Redirect(w, r, to.Unauthenticated, http.StatusFound)
	case d.Kind == denialUserInactive:
		http.Redirect(w, r, to.Deactivated, http.StatusFound)
	default:
		// denialUserLookupFailed, denialUnspecified, a kind added later that no
		// caller renders, and denialInvalidParams with no error attached all
		// land here. Denying is always a safe answer; issuing a code is not.
		to.ToClient("server_error", "An error occurred")
	}
}
