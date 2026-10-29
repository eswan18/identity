package internal

import (
	"fmt"
	"strings"

	"github.com/eswan18/identity/pkg/auth"
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

// ValidateAdminScopes rejects a client registration that grants admin scopes to
// a public client.
//
// Admin scopes are only ever issued through the client_credentials grant, which
// the server restricts to confidential clients, so a public client holding one
// can never obtain an admin token. Left unchecked, that registration is not
// dangerous -- the server refuses it either way -- but it is silently
// non-functional, and it looks exactly like a working admin client until
// someone tries to use it.
//
// The failure mode this prevents is a command that reads as correct:
//
//	identity-cli client create --name "Admin Tool" \
//	  --redirect-uris "https://tool.example.com/callback" \
//	  --scopes "admin:users:write"
//
// --confidential defaults to false, so this registers a public admin client.
// Before the server bound admin scopes to client_credentials, that was an
// escalation path: any user who could reach /oauth/authorize could consent to
// admin:* and redeem the code with only a client_id and their own PKCE
// verifier. Failing here states the requirement at the point the mistake is
// made.
func ValidateAdminScopes(scopes []string, isConfidential bool) error {
	if isConfidential {
		return nil
	}
	if adminScopes := auth.AdminScopesIn(scopes); len(adminScopes) > 0 {
		return fmt.Errorf(
			"scopes %s require a confidential client: admin scopes are only issued via the "+
				"client_credentials grant, so a public client can never obtain them - re-run with --confidential",
			strings.Join(adminScopes, ", "))
	}
	return nil
}

// ValidateTrustable refuses a client as trusted unless identity-cli
// registered it (kind "registered") and every one of its redirect URIs is
// exact and not loopback (redirecturi.UnsafeForTrustedClient). A trusted
// client gets user data with no consent screen, so:
//
//   - a metadata-document ("cimd") client, whose document, code and redirect
//     URIs belong to someone else, can never be trusted (the oauth_clients
//     CHECK constraint refuses it too; this gives the clear message);
//   - a wildcard redirect URI would hand a signed-in user's code, with no
//     interaction, to whoever can deploy a matching host, and a loopback one
//     to any program on the user's machine.
//
// Callers run it whenever the result would be a trusted client: creating one,
// trusting one, and changing the redirect URIs of one already trusted. See
// README, "Trusted (first-party) clients".
func ValidateTrustable(kind string, redirectURIs []string) error {
	if kind != "registered" {
		return fmt.Errorf("refusing to trust a %q client: only clients registered with identity-cli for apps the operator builds and controls can be trusted (see README, \"Trusted (first-party) clients\")", kind)
	}
	for _, uri := range redirectURIs {
		if why := redirecturi.UnsafeForTrustedClient(uri); why != "" {
			return fmt.Errorf("a trusted client may not have redirect URI %q: %s. A trusted client skips the consent screen, so it must have only exact, non-loopback redirect URIs; keep this client untrusted (it keeps the consent screen) or drop that URI (see README, \"Trusted (first-party) clients\")", uri, why)
		}
	}
	return nil
}
