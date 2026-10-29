package httpserver

import (
	"fmt"
	"log"
	"net/http"
	"slices"

	"github.com/eswan18/identity/pkg/db"
	"github.com/eswan18/identity/pkg/redirecturi"
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
	// denialResourceLookupFailed: the registry could not be read to resolve
	// the request's resource. A server error, never a verdict on the request.
	denialResourceLookupFailed
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
	// Resource is what the code, and the tokens it is exchanged for, will be
	// for: the request's resource parameter resolved against the registry, or
	// the client's default. nil means none (a token for identity itself).
	Resource *resolvedResource
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
//
// It takes the whole parsed request (authorizeParams) rather than the
// parameters it checks today, so a check on a parameter added later (resource,
// say) is a change here and in parseAuthorizeParams, not to every caller.
func (s *Server) checkCodeIssuance(
	r *http.Request,
	client db.OauthClient,
	p authorizeParams,
) (*codeIssuanceGrant, *codeIssuanceDenial) {
	if authErr := validateAuthorizeParams(client, p.ResponseType, p.CodeChallenge, p.CodeChallengeMethod, p.Scope); authErr != nil {
		return nil, &codeIssuanceDenial{Kind: denialInvalidParams, OAuthError: authErr}
	}
	if authErr := checkTrustedRedirect(client, p.RedirectURI); authErr != nil {
		return nil, &codeIssuanceDenial{Kind: denialInvalidParams, OAuthError: authErr}
	}

	// Which resource the request is for (RFC 8707), and whether its scopes
	// are ones identity or that resource defines. Checked before the session
	// so a bad request is refused at once rather than after a sign-in, and
	// after the pure checks above so a malformed request costs no lookup (a
	// request naming no resource for a client with no default costs none
	// either).
	resource, targetErr, err := s.resolveResource(r.Context(), client, p.Resource)
	if err != nil {
		log.Printf("checkCodeIssuance: %v", err)
		return nil, &codeIssuanceDenial{Kind: denialResourceLookupFailed}
	}
	if targetErr != nil {
		return nil, &codeIssuanceDenial{Kind: denialInvalidParams, OAuthError: targetErr}
	}
	if scopeErr := checkScopesAgainstResource(p.Scope, resource); scopeErr != nil {
		return nil, &codeIssuanceDenial{Kind: denialInvalidParams, OAuthError: scopeErr}
	}
	// A metadata-document client's allowed scopes are computed, not
	// registered: identity's user scopes plus the resolved resource's
	// (validateAuthorizeParams leaves this check to here, where the resource
	// is known). With no resource that is identity's scopes alone.
	if client.Kind == clientKindCIMD {
		if ok, invalid := containsAll(cimdAllowedScopes(resource), p.Scope); !ok {
			return nil, &codeIssuanceDenial{Kind: denialInvalidParams, OAuthError: &oauthAuthorizeError{
				"invalid_scope", fmt.Sprintf("Scopes %v not allowed for this client", invalid)}}
		}
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

	return &codeIssuanceGrant{Session: session, User: user, Resource: resource}, nil
}

// codeIssuanceRedirects is where a caller wants each class of denial to go.
// The two handlers differ here and only here: authorize is a browser navigation
// carrying the authorization request in its query string, consent is a form
// POST carrying it in a hidden field.
type codeIssuanceRedirects struct {
	// ToClient hands an OAuth error back to the client's redirect_uri per RFC
	// 6749 §4.1.2.1. Only safe once client_id and redirect_uri are validated.
	// Callers pass a closure over respondWithError, so the response carries iss
	// like every other authorization response.
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
		// denialUserLookupFailed, denialResourceLookupFailed,
		// denialUnspecified, a kind added later that no
		// caller renders, and denialInvalidParams with no error attached all
		// land here. Denying is always a safe answer; issuing a code is not.
		to.ToClient("server_error", "An error occurred")
	}
}

// checkTrustedRedirect refuses a trusted client's request whose redirect URI
// is not one it registered exactly, or is loopback. A trusted client skips the
// consent screen, so a code goes to its redirect URI with no interaction;
// identity-cli never lets a trusted client have a wildcard or loopback entry
// (README, "Trusted (first-party) clients"), and this keeps a row that got one
// some other way from being honoured: such a request mints nothing, rather
// than a code for a preview host or a local program.
func checkTrustedRedirect(client db.OauthClient, redirectURI string) *oauthAuthorizeError {
	if !client.Trusted {
		return nil
	}
	if !slices.Contains(client.RedirectUris, redirectURI) || redirecturi.UnsafeForTrustedClient(redirectURI) != "" {
		return &oauthAuthorizeError{"unauthorized_client",
			"A trusted client may only use an exact, non-loopback redirect URI"}
	}
	return nil
}
