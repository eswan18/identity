package httpserver

import (
	"encoding/json"
	"net/http"
	"slices"

	"github.com/eswan18/identity/pkg/auth"
	"github.com/eswan18/identity/pkg/config"
)

// Paths of the protocol endpoints that are fetched by machines rather than
// browsers. routes.go mounts them and ratelimit.go gives them the higher
// protocol budget, both from these constants, so the two cannot drift apart.
const (
	// openIDConfigurationPath is OIDC Discovery 1.0 §4.
	openIDConfigurationPath = "/.well-known/openid-configuration"
	// authorizationServerMetadataPath is RFC 8414 §3. The issuer has no path
	// component, so the well-known suffix sits at the root, beside the OIDC one.
	authorizationServerMetadataPath = "/.well-known/oauth-authorization-server"
	jwksPath                        = "/.well-known/jwks.json"
	tokenEndpointPath               = "/oauth/token"
)

// authorizationServerMetadata is the document served at both well-known
// paths. One document serves both: RFC 8414 §3 says OIDC's fields may appear
// in it, and OIDC Discovery requires jwks_uri, subject_types_supported and
// id_token_signing_alg_values_supported, which RFC 8414 permits.
//
// Every list is omitempty: RFC 8414 §3.2 says a parameter with zero elements
// MUST be omitted rather than sent as an empty array. Add a new field here
// (and set it in newAuthorizationServerMetadata) rather than writing a literal
// anywhere else.
type authorizationServerMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	UserinfoEndpoint      string `json:"userinfo_endpoint,omitempty"`
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`
	RevocationEndpoint    string `json:"revocation_endpoint,omitempty"`
	EndSessionEndpoint    string `json:"end_session_endpoint,omitempty"`

	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported,omitempty"`
	ResponseModesSupported            []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	SubjectTypesSupported             []string `json:"subject_types_supported,omitempty"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported,omitempty"`
	ClaimsSupported                   []string `json:"claims_supported,omitempty"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported,omitempty"`
}

// newAuthorizationServerMetadata builds the metadata document from config.
//
// The issuer is cfg.JWTIssuer verbatim: the same string signs every token's
// iss and prefixes the URLs the document is served from, so a client's
// byte-for-byte issuer comparison (RFC 8414 §3.3, OIDC Discovery §4.3) holds.
func newAuthorizationServerMetadata(cfg *config.Config) authorizationServerMetadata {
	issuer := cfg.JWTIssuer
	return authorizationServerMetadata{
		Issuer:                issuer,
		AuthorizationEndpoint: issuer + "/oauth/authorize",
		TokenEndpoint:         issuer + tokenEndpointPath,
		JWKSURI:               issuer + jwksPath,
		UserinfoEndpoint:      issuer + "/oauth/userinfo",
		IntrospectionEndpoint: issuer + "/oauth/introspect",
		RevocationEndpoint:    issuer + "/oauth/revoke",
		EndSessionEndpoint:    issuer + "/oauth/logout",

		// Identity's own scopes only. A resource's scopes are published by
		// that resource's protected resource metadata (RFC 9728), not here.
		ScopesSupported:        slices.Clone(auth.IdentityScopes),
		ResponseTypesSupported: []string{"code"},
		ResponseModesSupported: []string{"query"},
		GrantTypesSupported:    []string{"authorization_code", "refresh_token", "client_credentials"},
		// "none" is a public client (is_confidential=false), which presents
		// only its client_id and proves possession with PKCE.
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post", "client_secret_basic", "none"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"ES256"},
		ClaimsSupported: []string{
			"sub", "iss", "aud", "exp", "iat", "at_hash",
			"email", "email_verified",
			"preferred_username", "given_name", "family_name", "picture",
		},
		CodeChallengeMethodsSupported: []string{"S256"},
	}
}

// HandleOIDCDiscovery godoc
// @Summary      Authorization server metadata
// @Description  Returns the authorization server's metadata. The same document is served at /.well-known/openid-configuration (OpenID Connect Discovery 1.0) and /.well-known/oauth-authorization-server (RFC 8414).
// @Tags         oauth2
// @Produce      json
// @Success      200 {object} map[string]interface{} "Authorization server metadata"
// @Router       /.well-known/openid-configuration [get]
// @Router       /.well-known/oauth-authorization-server [get]
func (s *Server) HandleOIDCDiscovery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(newAuthorizationServerMetadata(s.config))
}
