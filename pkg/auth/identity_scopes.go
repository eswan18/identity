package auth

import "slices"

// OfflineAccessScope is the OIDC scope a client sends to ask to keep access
// while the user is away (OIDC Core §11). identity issues a refresh token on
// every authorization-code exchange regardless, so the scope changes nothing
// about the tokens; it is accepted and advertised because clients such as
// Claude look for it in the metadata and append it to their requests.
const OfflineAccessScope = "offline_access"

// IdentityScopes are the user-facing scopes identity defines itself, as
// opposed to scopes a resource server defines. They are what the metadata
// document advertises in scopes_supported. Admin scopes are identity's too,
// but they are obtainable only through client_credentials and so are not
// advertised.
var IdentityScopes = []string{"openid", "profile", "email", OfflineAccessScope}

// alwaysGrantableScopes are identity scopes any client may request on the
// authorization-code flow without having them in its allowed_scopes.
//
// Only offline_access is here. openid, profile and email stay gated by
// allowed_scopes, because they decide what a client may learn about the user,
// and a client registered for openid alone should not start receiving email
// addresses. offline_access discloses nothing: every code exchange already
// returns a refresh token.
var alwaysGrantableScopes = []string{OfflineAccessScope}

// IsAlwaysGrantableScope reports whether any client may request scope on the
// authorization-code flow regardless of its allowed_scopes.
func IsAlwaysGrantableScope(scope string) bool {
	return slices.Contains(alwaysGrantableScopes, scope)
}
