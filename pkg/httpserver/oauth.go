package httpserver

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/eswan18/identity/pkg/auth"
	"github.com/eswan18/identity/pkg/db"
	"github.com/eswan18/identity/pkg/views"
	"github.com/google/uuid"
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope"`
}

// handleOauthAuthorize godoc
// @Summary      OAuth2 authorization endpoint
// @Description  Validates OAuth2 parameters, checks if user is authenticated (via session cookie), renders login page if not authenticated, or generates authorization code and redirects to redirect_uri if authenticated. Every redirect back to the client carries iss (RFC 9207).
// @Tags         oauth2
// @Produce      html
// @Param        response_type        query     string  true  "Must be 'code'"
// @Param        client_id            query     string  true  "Registered client identifier"
// @Param        redirect_uri        query     string  true  "Where to send the user after auth"
// @Param        scope               query     string  false "Requested scopes (e.g., 'openid profile email'). Defaults to 'openid' if not provided."
// @Param        state               query     string  false "CSRF protection token. Recommended for OAuth flow."
// @Param        code_challenge      query     string  false "PKCE code challenge (SHA256 hash). Required for OAuth flow."
// @Param        code_challenge_method query   string  false "PKCE challenge method (must be 'S256'). Required for OAuth flow."
// @Param        resource            query     string  false "RFC 8707 resource indicator: the API the token is for. At most one; must be a registered resource the client may request. Defaults to the client's default resource."
// @Success      302 {string} string "Redirect to redirect_uri with authorization code, state and iss"
// @Failure      302 {string} string "Redirect to redirect_uri with error parameters, state and iss"
// @Router       /oauth/authorize [get]
func (s *Server) HandleOauthAuthorize(w http.ResponseWriter, r *http.Request) {
	p := parseAuthorizeParams(r.URL.Query())
	// The request as the client sent it, for the pages that may interrupt the
	// flow (login, consent) to carry and hand back unchanged.
	request := authorizeRequest(r.URL.RawQuery)

	// Phase 1: Validate client_id and redirect_uri first.
	// Per RFC 6749 4.1.2.1, if these are invalid we MUST NOT redirect — show error directly.
	if p.ClientID == "" {
		http.Error(w, "Client ID is required", http.StatusBadRequest)
		return
	}
	if p.RedirectURI == "" {
		http.Error(w, "Redirect URI is required", http.StatusBadRequest)
		return
	}
	client, err := s.validateOAuthClientRedirect(r.Context(), p.ClientID, p.RedirectURI)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// redirectError hands an OAuth error back to the client per RFC 6749 4.1.2.1.
	// Only safe to use after client_id and redirect_uri have been validated above.
	redirectError := func(errorCode, description string) {
		s.respondWithError(w, r, p, errorCode, description)
	}

	// Phase 2: Every precondition for issuing a code. These live in
	// checkCodeIssuance so HandleConsentPost -- the other code-minting path --
	// enforces exactly the same set; see code_issuance.go.
	grant, denial := s.checkCodeIssuance(r, client, p)
	if denial != nil {
		s.denyCodeIssuance(w, r, denial, codeIssuanceRedirects{
			ToClient: redirectError,
			// Carry the authorization request across the login so the user lands
			// back in this flow afterwards.
			Unauthenticated: request.loginURL(nil),
			Deactivated:     request.loginURL(url.Values{"error": {"account_deactivated"}}),
		})
		return
	}
	session := grant.Session

	// Phase 4: Check consent. If user hasn't consented to these scopes for this
	// resource, redirect to consent page. Consent is remembered per (user,
	// client, resource): approving one resource does not approve another.
	//
	// A trusted (first-party) client skips this phase and only this phase:
	// consent is implied, so there is no screen and no consent row (README,
	// "Trusted (first-party) clients"). Everything above -- client and
	// redirect_uri validation, PKCE, resource and scope checks, the session
	// (so login and MFA) and the active-account check -- has already run for
	// it exactly as for any other client.
	if !client.Trusted {
		consent, err := s.datastore.Q.GetUserConsent(r.Context(), db.GetUserConsentParams{
			UserID:   session.UserID,
			ClientID: client.ID,
			Resource: grant.Resource.uri(),
		})
		scopesOK, _ := containsAll(consent.Scopes, p.Scope)
		if err != nil || !scopesOK {
			http.Redirect(w, r, request.consentURL(), http.StatusFound)
			return
		}
	}

	// Phase 5: Generate authorization code and redirect.
	authorizationCode, err := s.generateAuthorizationCode(r.Context(), session.UserID, client.ID, p.RedirectURI, p.Scope, p.CodeChallenge, p.CodeChallengeMethod, p.Nonce, grant.Resource.uri())
	if err != nil {
		redirectError("server_error", "An error occurred")
		return
	}
	s.respondWithCode(w, r, p, authorizationCode)
}

// handleOauthToken godoc
// @Summary      OAuth2 token endpoint
// @Description  Exchanges authorization code for access/refresh/ID tokens (with PKCE verification) or refreshes access token using refresh token
// @Tags         oauth2
// @Accept       application/x-www-form-urlencoded
// @Produce      json
// @Param        grant_type          formData  string  true  "Grant type: 'authorization_code' or 'refresh_token'"
// @Param        code                formData  string  false "Authorization code (required for authorization_code grant)"
// @Param        redirect_uri        formData  string  false "Redirect URI (required for authorization_code grant)"
// @Param        client_id           formData  string  true  "OAuth client ID"
// @Param        client_secret       formData  string  true  "OAuth client secret"
// @Param        code_verifier       formData  string  false "PKCE code verifier (required for authorization_code grant)"
// @Param        refresh_token       formData  string  false "Refresh token (required for refresh_token grant)"
// @Param        resource            formData  string  false "RFC 8707 resource indicator. authorization_code and refresh_token: optional, and must name the resource the grant is for. client_credentials: a resource the client may request (defaults to its default resource)."
// @Success      200 {object} map[string]interface{} "Token response with access_token, token_type, expires_in, refresh_token, scope, and id_token (when openid scope requested)"
// @Failure      400 {object} map[string]string "OAuth2 error response (invalid_request, invalid_grant, invalid_target, unsupported_grant_type, etc.)"
// @Failure      401 {object} map[string]string "OAuth2 error response (invalid_client)"
// @Failure      500 {object} map[string]string "OAuth2 error response for a failure on our side (server_error) - retryable, and not a verdict on the grant"
// @Router       /oauth/token [post]
func (s *Server) HandleOauthToken(w http.ResponseWriter, r *http.Request) {
	grantType := r.FormValue("grant_type")

	client, err := s.authenticateClient(r)
	if err != nil {
		// A lookup that failed is not a rejected client. This fires before
		// either grant handler, so in a full database outage it is the ONLY
		// thing a client sees -- and invalid_client is a credentials verdict.
		if errors.Is(err, ErrClientLookupFailed) {
			s.writeTokenError(w, "server_error", "Failed to look up client")
			return
		}
		s.writeInvalidClientError(w)
		return
	}

	switch grantType {
	case "authorization_code":
		s.handleAuthorizationCodeGrant(w, r, client)
	case "refresh_token":
		s.handleRefreshTokenGrant(w, r, client)
	case "client_credentials":
		s.handleClientCredentialsGrant(w, r, client)
	default:
		s.writeTokenError(w, "unsupported_grant_type", "Grant type must be 'authorization_code', 'refresh_token', or 'client_credentials'")
	}
}

// isValidCodeVerifier reports whether verifier has a valid PKCE code-verifier
// length per RFC 7636 §4.1 (43-128 characters). We deliberately do NOT enforce
// the "unreserved" character set here: the verifier is generated by the client,
// and some clients emit base64url values that retain '=' padding (which is
// outside the unreserved set). Rejecting those would break existing clients,
// and a verifier with unexpected characters simply won't match the stored
// code_challenge below anyway. The length bound is the useful part — it caps
// the input before hashing and enforces the RFC's minimum entropy floor.
func isValidCodeVerifier(verifier string) bool {
	return len(verifier) >= 43 && len(verifier) <= 128
}

// handleAuthorizationCodeGrant exchanges an authorization code for tokens
func (s *Server) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request, client db.OauthClient) {
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")

	if code == "" {
		s.writeTokenError(w, "invalid_request", "Authorization code is required")
		return
	}

	// Look up the authorization code
	authCode, err := s.datastore.Q.GetAuthorizationCode(r.Context(), code)
	if err != nil {
		code, description := lookupFailure(err, "authorization code")
		s.writeTokenError(w, code, description)
		return
	}

	// Validate the code hasn't been consumed
	if authCode.ConsumedAt.Valid {
		s.writeTokenError(w, "invalid_grant", "Authorization code has already been used")
		return
	}

	// Validate the code hasn't expired
	if authCode.ExpiresAt.Before(time.Now()) {
		s.writeTokenError(w, "invalid_grant", "Authorization code has expired")
		return
	}

	// Validate the client ID matches
	if authCode.ClientID != client.ID {
		s.writeTokenError(w, "invalid_grant", "Authorization code was not issued to this client")
		return
	}

	// Validate the redirect URI matches
	if authCode.RedirectUri != redirectURI {
		s.writeTokenError(w, "invalid_grant", "Redirect URI does not match")
		return
	}

	// The resource was resolved at authorize time and recorded on the code.
	// A resource parameter here is optional and may only repeat it (RFC 8707
	// §2.2). Checked before the code is consumed, like the checks above, so a
	// client that sent a wrong one can retry with the code still good.
	resource := s.grantedResource(authCode.Resource, client.DefaultResource)
	if description := checkTokenRequestResource(tokenRequestResource(r), resource); description != "" {
		s.writeTokenError(w, errInvalidTarget, description)
		return
	}

	// Verify PKCE code_verifier
	if authCode.CodeChallenge.Valid {
		if codeVerifier == "" {
			s.writeTokenError(w, "invalid_request", "Code verifier is required")
			return
		}
		// Bound the verifier length per RFC 7636 §4.1 (43-128 chars) before
		// hashing it. This caps the hash input and enforces the RFC's minimum;
		// an out-of-range verifier can never match a validly-generated
		// challenge, so this is an early rejection with the same invalid_grant
		// outcome as a verifier that fails the hash comparison below.
		if !isValidCodeVerifier(codeVerifier) {
			s.writeTokenError(w, "invalid_grant", "Invalid code verifier")
			return
		}
		// Compute SHA256 hash of the verifier
		hash := sha256.Sum256([]byte(codeVerifier))
		computedChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

		// Normalize both challenges for comparison (handles any legacy padded data)
		// The stored challenge should already be normalized, but we normalize both
		// to be safe and handle edge cases.
		if normalizeCodeChallenge(computedChallenge) != normalizeCodeChallenge(authCode.CodeChallenge.String) {
			s.writeTokenError(w, "invalid_grant", "Invalid code verifier")
			return
		}
	}

	// Atomically mark the authorization code as consumed. The WHERE clause
	// guards against TOCTOU: if the earlier `authCode.ConsumedAt.Valid` check
	// passed but a concurrent request already consumed the code in the meantime,
	// this UPDATE affects 0 rows and we refuse to issue tokens. RFC 6749 §10.5
	// requires that an authorization code be usable at most once.
	rowsAffected, err := s.datastore.Q.ConsumeAuthorizationCode(r.Context(), code)
	if err != nil {
		s.writeTokenError(w, "server_error", "Failed to consume authorization code")
		return
	}
	if rowsAffected == 0 {
		s.writeTokenError(w, "invalid_grant", "Authorization code has already been used")
		return
	}

	// Generate tokens, passing nonce for inclusion in the ID token
	nonce := ""
	if authCode.Nonce.Valid {
		nonce = authCode.Nonce.String
	}
	// A code exchange is a sign-in, so it starts a refresh-token family.
	family, err := newFamilyID()
	if err != nil {
		s.writeTokenError(w, "server_error", "Failed to generate tokens")
		return
	}
	// The token is for the resource the code was issued for (none: identity
	// itself), never the client's current default.
	//
	// For a client that asks for consent, the tokens are stored only if the
	// user's consent is still there, checked atomically with the insert: the
	// user may have disconnected the app since authorize found the consent and
	// issued this code. A trusted client has no consent to check.
	tokens, err := s.generateTokens(r.Context(), client.ID, authCode.UserID, authCode.Scope, nonce, resource, family, !client.Trusted)
	if errors.Is(err, errConsentWithdrawn) {
		s.writeTokenError(w, "invalid_grant", "The user has withdrawn consent for this client")
		return
	}
	if err != nil {
		s.writeTokenError(w, "server_error", "Failed to generate tokens")
		return
	}
	s.writeTokens(w, tokens)
}

// tokenRequestResource is every resource parameter a token request carried.
func tokenRequestResource(r *http.Request) []string {
	if err := r.ParseForm(); err != nil {
		return nil
	}
	return r.Form["resource"]
}

// handleRefreshTokenGrant exchanges a refresh token for new tokens, spending it
// (rotation). Presenting a refresh token that was already spent revokes its
// whole family (reuse detection; see refresh_families.go). Every refusal of a
// dead refresh token is invalid_grant.
func (s *Server) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, client db.OauthClient) {
	refreshToken := r.FormValue("refresh_token")

	if refreshToken == "" {
		s.writeTokenError(w, "invalid_request", "Refresh token is required")
		return
	}

	// Look up the token by refresh token, revoked or not: how a revoked token
	// died decides what presenting it again means.
	token, err := s.datastore.Q.GetTokenByRefreshTokenIncludingRevoked(r.Context(), sql.NullString{String: refreshToken, Valid: true})
	if err != nil {
		code, description := lookupFailure(err, "refresh token")
		s.writeTokenError(w, code, description)
		return
	}

	// Validate the client ID matches
	if token.ClientID != client.ID {
		s.writeTokenError(w, "invalid_grant", "Refresh token was not issued to this client")
		return
	}

	// Check if refresh token has expired. This comes before the revocation
	// check, so an expired token is refused as expired whether or not it was
	// rotated: the cleanup sweep deletes rotated rows once they expire, and the
	// answer must not depend on whether it has run yet.
	if token.RefreshExpiresAt.Valid && token.RefreshExpiresAt.Time.Before(time.Now()) {
		s.writeTokenError(w, "invalid_grant", "Refresh token has expired")
		return
	}

	if token.RevokedAt.Valid {
		s.refuseRevokedRefreshToken(r.Context(), w, client, token)
		return
	}

	// The family this refresh continues, which may not go on past its absolute
	// lifetime however recently it was refreshed.
	family := tokenFamily(token)
	if familyExpired(family, time.Now()) {
		s.writeTokenError(w, "invalid_grant", "Refresh token has reached the maximum lifetime of its sign-in")
		return
	}

	// Check if user is still active (deactivated users cannot refresh tokens)
	if token.UserID.Valid {
		user, err := s.datastore.Q.GetUserByIDIncludingInactive(r.Context(), token.UserID.UUID)
		if err != nil {
			s.writeTokenError(w, "server_error", "Failed to verify user status")
			return
		}
		if !user.IsActive {
			s.writeTokenError(w, "invalid_grant", "Account deactivated")
			return
		}
	}

	// Refuse to carry admin scopes forward.
	//
	// validateAuthorizeParams now prevents an authorization code from ever
	// carrying admin:*, and client_credentials issues no refresh token at all
	// (see generateServiceAccountTokens), so a refresh token holding one is
	// anomalous by construction -- it can only be a token minted before that
	// rule existed. Rejecting here means the rule cannot be outlived by a token
	// issued under the old one, for up to the 30-day refresh lifetime.
	//
	// The token is deliberately not consumed: this rejects the grant rather than
	// spending the credential, matching how every other validation failure above
	// behaves.
	if adminScopes := auth.AdminScopesIn(token.Scope); len(adminScopes) > 0 {
		log.Printf("handleRefreshTokenGrant: refusing refresh token carrying admin scopes %v for client %s",
			adminScopes, client.ClientID)
		s.writeTokenError(w, "invalid_scope",
			"Refresh tokens may not carry admin scopes; use the client_credentials grant")
		return
	}

	// The resource is the one stored on the token, and a resource parameter
	// may only repeat it (spec, section 3): a refresh never widens a grant or
	// re-points it. A stored issuer is a token for identity itself, for which
	// no resource may be named. Checked before anything is minted or spent, so
	// a refused request leaves the refresh token usable.
	if description := checkTokenRequestResource(tokenRequestResource(r), s.grantedResource(token.Resource, sql.NullString{})); description != "" {
		s.writeTokenError(w, errInvalidTarget, description)
		return
	}

	// Mint the replacement tokens (same user, scope and resource, same family;
	// no nonce on refresh), then spend the presented token. The resource is the
	// one stored on the token being refreshed, never the client's current
	// default: changing a client's default must not re-point tokens already
	// granted, and a refresh must never widen a grant.
	var userID uuid.UUID
	if token.UserID.Valid {
		userID = token.UserID.UUID
	}
	tokens, err := s.generateTokens(r.Context(), client.ID, userID, token.Scope, "", token.Resource, family, false)
	if err != nil {
		s.writeTokenError(w, "server_error", "Failed to generate tokens")
		return
	}

	// Atomically spend the presented token. The WHERE clause (refresh_token =
	// $1 AND revoked_at IS NULL) guards against TOCTOU: if two concurrent
	// requests both pass the validation above with the same refresh token, only
	// one UPDATE affects a row, and only that request hands out its tokens
	// (RFC 6749 §10.5; ConsumeAuthorizationCode does the same for codes).
	//
	// The loser is a reuse, and with no grace window (spec decision 2) it
	// revokes the family -- the winner's new tokens included. That only works if
	// the loser can see them, which is why the replacement is inserted BEFORE
	// the rotation rather than after. The winner's insert commits before its
	// rotation, and the loser learns it lost only once that rotation has
	// committed (its own UPDATE waits on the row lock and re-checks, or its
	// lookup already saw the token rotated), so the loser's family revocation,
	// a later statement, always sees the winner's row. Inserted after the
	// rotation instead, the winner's tokens could land just after the loser's
	// family revocation had looked, and survive it. No transaction needed, and
	// no round trip added.
	rowsAffected, err := s.datastore.Q.RotateRefreshToken(r.Context(), db.RotateRefreshTokenParams{
		RefreshToken: sql.NullString{String: refreshToken, Valid: true},
		FamilyID:     family,
	})
	if err != nil {
		if _, revokeErr := s.datastore.Q.RevokeTokenByRefreshToken(r.Context(), db.RevokeTokenByRefreshTokenParams{
			RefreshToken: sql.NullString{String: tokens.RefreshToken, Valid: true},
			Reason:       string(revokedRevoked),
		}); revokeErr != nil {
			log.Printf("[ERROR] handleRefreshTokenGrant: client %s: failed to revoke unissued tokens: %v", client.ClientID, revokeErr)
		}
		s.writeTokenError(w, "server_error", "Failed to revoke old token")
		return
	}
	if rowsAffected == 0 {
		s.refuseLostRotation(r.Context(), w, client, refreshToken, tokens.RefreshToken)
		return
	}

	s.writeTokens(w, tokens)
}

// writeTokens writes a successful token response.
func (s *Server) writeTokens(w http.ResponseWriter, tokens TokenPair) {
	response := TokenResponse{
		AccessToken:  tokens.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    tokens.ExpiresIn,
		RefreshToken: tokens.RefreshToken,
		IDToken:      tokens.IDToken,
		Scope:        strings.Join(tokens.Scope, " "),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(response)
}

// handleClientCredentialsGrant handles the client_credentials grant type for service-to-service auth.
// No user is involved - the client authenticates as itself.
func (s *Server) handleClientCredentialsGrant(w http.ResponseWriter, r *http.Request, client db.OauthClient) {
	// A metadata-document client only ever acts for a signed-in user. It is
	// never confidential, so the check below would refuse it too; this says
	// so explicitly, and keeps it refused whatever its row says.
	if client.Kind == clientKindCIMD {
		s.writeTokenError(w, "unauthorized_client", "Client credentials grant is not available to metadata-document clients")
		return
	}
	// Client credentials grant requires a confidential client
	if !client.IsConfidential {
		s.writeTokenError(w, "unauthorized_client", "Client credentials grant requires a confidential client")
		return
	}

	// Parse requested scopes (optional, defaults to all allowed scopes)
	scopeParam := r.FormValue("scope")
	var requestedScopes []string
	if scopeParam == "" {
		// offline_access means "on the user's behalf while they are away"; a
		// client acting as itself has no user to be away. Leave it out of the
		// default even if a registration lists it.
		requestedScopes = slices.DeleteFunc(slices.Clone(client.AllowedScopes), func(sc string) bool {
			return sc == auth.OfflineAccessScope
		})
	} else {
		requestedScopes = strings.Split(scopeParam, " ")
	}
	if slices.Contains(requestedScopes, auth.OfflineAccessScope) {
		s.writeTokenError(w, "invalid_scope", "offline_access is not available with the client_credentials grant")
		return
	}

	// Validate requested scopes against client's allowed_scopes
	if allowed, invalidScopes := containsAll(client.AllowedScopes, requestedScopes); !allowed {
		s.writeTokenError(w, "invalid_scope", fmt.Sprintf("Scopes %v not allowed for this client", invalidScopes))
		return
	}

	// The resource is resolved as on /oauth/authorize: one the client may
	// request, else its default, else none (aud = issuer, which the admin API
	// requires). Scopes stay governed by allowed_scopes alone here: a service
	// client acts as itself, and its scopes (admin:* among them) are
	// registered against it, not defined by the resource.
	resource, targetErr, err := s.resolveResource(r.Context(), client, tokenRequestResource(r))
	if err != nil {
		log.Printf("handleClientCredentialsGrant: %v", err)
		s.writeTokenError(w, "server_error", "Failed to resolve resource")
		return
	}
	if targetErr != nil {
		s.writeTokenError(w, targetErr.Code, targetErr.Description)
		return
	}

	// Generate service account token (no user, no refresh token)
	s.writeClientCredentialsTokenResponse(w, r, client, requestedScopes, resource.uri())
}

// writeClientCredentialsTokenResponse generates service account tokens and writes the JSON response.
// Per OAuth2 spec, client_credentials does not include a refresh token.
func (s *Server) writeClientCredentialsTokenResponse(w http.ResponseWriter, r *http.Request, client db.OauthClient, scope []string, resource sql.NullString) {
	tokens, err := s.generateServiceAccountTokens(r.Context(), client, scope, resource)
	if err != nil {
		log.Printf("writeClientCredentialsTokenResponse: failed to generate tokens: %v", err)
		s.writeTokenError(w, "server_error", "Failed to generate tokens")
		return
	}

	// Note: No refresh_token in response per OAuth 2.0 spec for client_credentials
	response := map[string]interface{}{
		"access_token": tokens.AccessToken,
		"token_type":   "Bearer",
		"expires_in":   tokens.ExpiresIn,
		"scope":        strings.Join(tokens.Scope, " "),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(response)
}

// writeClientAuthError answers a failed client authentication on the endpoints
// that require a confidential client.
//
// A lookup that never reached an answer is not a rejected client. Reporting it
// as invalid_client tells a resource server its own credentials are wrong --
// during an outage, on an endpoint it hits for every request it serves.
func (s *Server) writeClientAuthError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrClientLookupFailed) {
		writeJSONError(w, http.StatusInternalServerError, "server_error", "Failed to look up client")
		return
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="oauth"`)
	writeJSONError(w, http.StatusUnauthorized, "invalid_client", "Client authentication required")
}

// lookupFailure gives the OAuth error code AND description for a row lookup
// that failed. They travel together because they must agree: a body reading
// {"error":"server_error","error_description":"Invalid refresh token"} tells a
// client one thing in the field this PR asks it to branch on and the opposite
// in the field a human reads.
//
// Only "no such row" is a verdict on what was being looked up. Every other
// error is the lookup itself failing -- a dropped connection, a statement
// timeout -- which says nothing about the token, code or client involved.
// Collapsing the two is how a database blip came to tell healthy clients their
// grant was dead, so the distinction is made here once rather than at each site.
func lookupFailure(err error, subject string) (code, description string) {
	if errors.Is(err, sql.ErrNoRows) {
		return "invalid_grant", "Invalid " + subject
	}
	return "server_error", "Failed to look up " + subject
}

// tokenErrorStatus gives the HTTP status for the token-endpoint error codes that
// report a failure of ours rather than a defect in the request. Anything absent
// here is the caller's problem and gets RFC 6749 §5.2's default 400.
//
// §5.2 governs this endpoint and defines neither code, so emitting them here is
// an extension this service already made long before this mapping existed. The
// statuses are chosen to match: RFC 6749 pairs `server_error` with 500 and
// `temporarily_unavailable` with 503 at the authorization endpoint (§4.1.2.1),
// and this codebase already uses those same two statuses for the same two ideas
// everywhere else (writeAdminError, userinfo, introspect, revoke).
var tokenErrorStatus = map[string]int{
	"server_error":            http.StatusInternalServerError,
	"temporarily_unavailable": http.StatusServiceUnavailable,
}

// writeTokenError writes an OAuth2 error response for the token endpoint.
//
// The status is chosen from the error code rather than fixed at 400. RFC 6749
// §5.2 mandates 400 for the errors it enumerates -- all of which describe
// something wrong with the *request* -- and `server_error` is deliberately not
// among them. Answering 400 for it says "your request was bad" when the truth
// is "our database just failed", and every client then has to parse the body to
// learn otherwise. Three of them did not, and signed users out of healthy
// sessions on a transient database blip; see the write-ups on
// footstrike-ios#22 and haruspex#205.
//
// A 503 makes the honest answer the default one: a client that only inspects
// the status retries instead of ending the session, and one that reads the body
// still gets the same error code it did before.
func (s *Server) writeTokenError(w http.ResponseWriter, errorCode, description string) {
	status, ok := tokenErrorStatus[errorCode]
	if !ok {
		status = http.StatusBadRequest
	}
	writeJSONError(w, status, errorCode, description)
}

// writeInvalidClientError writes the invalid_client error for the token endpoint.
// Per RFC 6749 §5.2, a failed client authentication attempt at the token endpoint
// must be reported as HTTP 401 (not the 400 used for other token errors), with a
// WWW-Authenticate header. This matches the invalid_client handling already used
// by the introspection and revocation endpoints (see their writeJSONError call
// sites for the same error code).
func (s *Server) writeInvalidClientError(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="oauth"`)
	writeJSONError(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials")
}

// writeUserInfoUnauthorized writes a 401 JSON error for the UserInfo endpoint,
// including a WWW-Authenticate header per RFC 6750 §3. Unlike the token,
// introspection, and revocation endpoints (which authenticate the *client* via
// HTTP Basic and so challenge with `Basic realm="oauth"` — see
// writeInvalidClientError), UserInfo is a Bearer-token-protected resource: a
// missing, invalid, or revoked bearer token must be challenged with the Bearer
// scheme instead. The errorCode/description are echoed into both the header
// and the JSON body so the two agree.
func writeUserInfoUnauthorized(w http.ResponseWriter, errorCode, description string) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error=%q, error_description=%q`, errorCode, description))
	writeJSONError(w, http.StatusUnauthorized, errorCode, description)
}

// handleUserInfo godoc
// @Summary      OIDC UserInfo endpoint
// @Description  Returns user identity claims for the authenticated user. Claims are gated by scope per OIDC Core Section 5.4: "sub" is always returned; "email" and "email_verified" require the "email" scope; "username", "given_name", "family_name", and "picture" require the "profile" scope. Supports both GET and POST per OIDC Core Section 5.3; on POST, the access token may alternatively be sent as a form-encoded "access_token" parameter (RFC 6750 Section 2.2) instead of the Authorization header.
// @Tags         oidc
// @Produce      json
// @Security     BearerAuth
// @Param        Authorization header string false "Bearer access token"
// @Param        access_token  formData string false "Access token (POST form-encoded alternative to the Authorization header)"
// @Success      200 {object} map[string]interface{} "User identity claims (scope-dependent)"
// @Failure      401 {object} map[string]string "Unauthorized - invalid or missing access token"
// @Router       /oauth/userinfo [get]
// @Router       /oauth/userinfo [post]
//
// NOTE: docs/ (swagger.json / swagger.yaml / docs.go) is generated by `swag
// init` and is NOT regenerated here - doing so needs toolchain deps not
// present in this environment. The annotations above are updated so a future
// `swag init` run picks up the POST route and the form-body access_token
// parameter; until then, docs/ still only reflects the GET-only shape.
func (s *Server) HandleOauthUserInfo(w http.ResponseWriter, r *http.Request) {
	// Resolve the access token. Per OIDC Core §5.3.1 / RFC 6750, the
	// Authorization: Bearer header is the primary transport for both GET and
	// POST. POST additionally MAY carry the token as a form-encoded
	// "access_token" parameter (RFC 6750 §2.2), which we fall back to only
	// when there's no Bearer header and the request is a POST - deliberately
	// not for GET, so a plain "?access_token=..." query string (the
	// URI-query-parameter method OIDC discourages) is never picked up here.
	// RFC 6750 §2 says a client MUST NOT use more than one method to send the
	// token; if both are present we simply prefer the header.
	authHeader := r.Header.Get("Authorization")
	var accessToken string
	switch {
	case strings.HasPrefix(authHeader, "Bearer "):
		accessToken = strings.TrimPrefix(authHeader, "Bearer ")
	case r.Method == http.MethodPost:
		accessToken = r.FormValue("access_token")
	}

	if accessToken == "" {
		writeUserInfoUnauthorized(w, "invalid_token", "Missing or invalid Authorization header")
		return
	}

	// Validate the JWT and extract claims
	// Note: We don't validate audience here since this is the identity provider's own endpoint.
	// Audience validation is done by resource servers (like the fitness API).
	claims, err := s.jwtGenerator.ValidateToken(accessToken, "")
	if err != nil {
		// Log the detailed error server-side, but return generic error to client
		// to avoid leaking information about token structure or validation logic
		log.Printf("JWT validation failed: %v", err)
		writeUserInfoUnauthorized(w, "invalid_token", "Invalid or expired access token")
		return
	}

	// Check if the token has been revoked by looking up its JTI. Every access
	// token this server issues (see generateTokens/generateServiceAccountTokens
	// in credentials.go) gets a corresponding row inserted into oauth_tokens at
	// issuance time, and GetTokenByAccessToken's query already filters out rows
	// where revoked_at IS NOT NULL or expires_at has passed. So sql.ErrNoRows
	// here means the token was revoked (or has expired at the DB level), not
	// that revocation tracking is unavailable - it must be rejected, mirroring
	// introspectAccessToken's handling of the same lookup.
	if _, live, err := s.liveAccessToken(r.Context(), claims.ID); err != nil {
		log.Printf("HandleOauthUserInfo: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "server_error", "Failed to verify token status")
		return
	} else if !live {
		writeUserInfoUnauthorized(w, "invalid_token", "Token has been revoked")
		return
	}

	// UserInfo serves only tokens obtained through OpenID Connect
	// authentication (OIDC Core §5.3), i.e. ones granted the openid scope. A
	// token issued for some other API -- an MCP client's, carrying only that
	// API's scopes -- must not double as a key to the user's profile. Every
	// login client requests openid, so none of them is affected.
	scopes := strings.Split(claims.Scope, " ")
	if !slices.Contains(scopes, "openid") {
		writeUserInfoUnauthorized(w, "invalid_token", "Access token was not issued with the openid scope")
		return
	}

	// Return OIDC standard claims from JWT.
	// Only "sub" is always included; other claims are gated by scope per OIDC Core Section 5.4.
	userInfo := map[string]interface{}{
		"sub": claims.Subject,
	}

	// "email" scope: email and email_verified
	if slices.Contains(scopes, "email") {
		userInfo["email"] = claims.Email
		userInfo["email_verified"] = claims.EmailVerified
	}

	// "profile" scope: username and profile fields from DB
	if slices.Contains(scopes, "profile") {
		userInfo["username"] = claims.Username
		userID, err := uuid.Parse(claims.Subject)
		if err == nil {
			user, err := s.datastore.Q.GetUserByID(r.Context(), userID)
			if err == nil {
				if user.GivenName.Valid {
					userInfo["given_name"] = user.GivenName.String
				}
				if user.FamilyName.Valid {
					userInfo["family_name"] = user.FamilyName.String
				}
				if user.Picture.Valid {
					userInfo["picture"] = user.Picture.String
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(userInfo)
}

// handleIntrospect godoc
// @Summary      Token introspection endpoint
// @Description  Returns metadata about a token (validity, scopes, expiration, etc.) per RFC 7662. This is different from /userinfo which returns user identity - introspect returns token information.
// @Tags         oauth2
// @Accept       application/x-www-form-urlencoded
// @Produce      json
// @Param        token           formData  string  true  "The token to introspect (access token or refresh token)"
// @Param        token_type_hint formData  string  false "Hint about the token type: 'access_token' or 'refresh_token'"
// @Param        client_id       formData  string  true  "OAuth client ID"
// @Param        client_secret   formData  string  true  "OAuth client secret"
// @Success      200 {object} map[string]interface{} "Token introspection response with 'active' (boolean), 'scope', 'exp', 'iat', 'sub', etc."
// @Failure      400 {object} map[string]string "Invalid request"
// @Failure      401 {object} map[string]string "Unauthorized - invalid client credentials"
// @Router       /oauth/introspect [post]
func (s *Server) HandleIntrospect(w http.ResponseWriter, r *http.Request) {
	token := r.FormValue("token")
	tokenTypeHint := r.FormValue("token_type_hint")

	// Authenticate the calling client. Per RFC 7662 §2.1, the introspection endpoint MUST be
	// protected against unauthorized callers, so we require a fully authenticated confidential
	// client (client_id + client_secret) rather than the token endpoint's laxer public-client
	// allowance.
	_, err := s.authenticateConfidentialClient(r)
	if err != nil {
		s.writeClientAuthError(w, err)
		return
	}

	if token == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "Token parameter is required")
		return
	}

	// Try to introspect based on hint, or try both if no hint
	var response map[string]interface{}

	if tokenTypeHint == "refresh_token" {
		response, err = s.introspectRefreshToken(r.Context(), token)
	} else {
		// Try access token first. With no hint, or a hint we don't know, fall
		// back to treating it as a refresh token.
		response, err = s.introspectAccessToken(r.Context(), token)
		if err == nil && !response["active"].(bool) && tokenTypeHint != "access_token" {
			response, err = s.introspectRefreshToken(r.Context(), token)
		}
	}
	if err != nil {
		log.Printf("HandleIntrospect: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "server_error", "Failed to verify token status")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// introspectAccessToken attempts to introspect a JWT access token.
// Returns the introspection response and an error. If the error is non-nil,
// the caller should return a server error to the client.
func (s *Server) introspectAccessToken(ctx context.Context, token string) (map[string]interface{}, error) {
	inactive := map[string]interface{}{"active": false}

	// Parse the JWT without audience validation (resource server may have different audience)
	claims, err := s.jwtGenerator.ValidateToken(token, "")
	if err != nil {
		return inactive, nil
	}

	// Check if the token has been revoked by looking up the JTI
	dbToken, live, err := s.liveAccessToken(ctx, claims.ID)
	if err != nil {
		// Could not determine revocation status; the caller turns this into a
		// server error rather than reporting the token inactive, since "unknown"
		// and "not active" are different answers.
		return nil, err
	}
	if !live {
		return inactive, nil
	}

	clientID, err := s.publicClientID(ctx, dbToken.ClientID)
	if err != nil {
		return nil, err
	}

	// Token is valid and not revoked
	response := map[string]interface{}{
		"active":     true,
		"scope":      claims.Scope,
		"client_id":  clientID,
		"username":   claims.Username,
		"token_type": "Bearer",
		"exp":        claims.ExpiresAt.Unix(),
		"iat":        claims.IssuedAt.Unix(),
		"sub":        claims.Subject,
		"iss":        claims.Issuer,
		"jti":        claims.ID,
	}

	if len(claims.Audience) > 0 {
		response["aud"] = claims.Audience[0]
	}

	return response, nil
}

// publicClientID maps a client's internal id (what oauth_tokens references) to
// the client_id it is known by everywhere else. Introspection reports the
// latter, per RFC 7662 §2.2; it used to leak the internal UUID instead.
func (s *Server) publicClientID(ctx context.Context, id uuid.UUID) (string, error) {
	client, err := s.datastore.Q.GetOAuthClientByID(ctx, id)
	if err != nil {
		return "", fmt.Errorf("looking up the client a token was issued to: %w", err)
	}
	return client.ClientID, nil
}

// introspectRefreshToken attempts to introspect a refresh token. As with
// introspectAccessToken, a non-nil error means the answer is unknown, not
// inactive, and the caller reports a server error.
func (s *Server) introspectRefreshToken(ctx context.Context, token string) (map[string]interface{}, error) {
	dbToken, err := s.datastore.Q.GetTokenByRefreshToken(ctx, sql.NullString{String: token, Valid: true})
	if err != nil {
		return map[string]interface{}{"active": false}, nil
	}

	// Check if refresh token is expired
	if dbToken.RefreshExpiresAt.Valid && dbToken.RefreshExpiresAt.Time.Before(time.Now()) {
		return map[string]interface{}{"active": false}, nil
	}

	clientID, err := s.publicClientID(ctx, dbToken.ClientID)
	if err != nil {
		return nil, err
	}

	// Get user info for the response
	user, err := s.datastore.Q.GetUserByID(ctx, dbToken.UserID.UUID)
	username := ""
	if err == nil {
		username = user.Username
	}

	response := map[string]interface{}{
		"active":     true,
		"scope":      strings.Join(dbToken.Scope, " "),
		"client_id":  clientID,
		"username":   username,
		"token_type": "refresh_token",
		"iat":        dbToken.CreatedAt.Unix(),
		"sub":        dbToken.UserID.UUID.String(),
	}

	// Per RFC 7662, "exp" should only be present when the token actually expires.
	// RefreshExpiresAt is a nullable column (NULL means the refresh token does not
	// expire), so unconditionally taking .Time.Unix() would emit the zero-value
	// time's epoch (a bogus negative/zero "exp") for non-expiring refresh tokens.
	if dbToken.RefreshExpiresAt.Valid {
		response["exp"] = dbToken.RefreshExpiresAt.Time.Unix()
	}

	return response, nil
}

// handleRevoke godoc
// @Summary      Token revocation endpoint
// @Description  Revokes a specific access token or refresh token per RFC 7009. This is more granular than /logout which invalidates all user tokens - revoke can invalidate individual tokens.
// @Tags         oauth2
// @Accept       application/x-www-form-urlencoded
// @Produce      json
// @Param        token           formData  string  true  "The token to revoke (access token or refresh token)"
// @Param        token_type_hint formData  string  false "Hint about the token type: 'access_token' or 'refresh_token'"
// @Param        client_id       formData  string  true  "OAuth client ID"
// @Param        client_secret   formData  string  true  "OAuth client secret"
// @Success      200 {string} string "Token revoked successfully"
// @Failure      400 {object} map[string]string "Invalid request"
// @Failure      401 {object} map[string]string "Unauthorized - invalid client credentials"
// @Router       /oauth/revoke [post]
func (s *Server) HandleOauthRevoke(w http.ResponseWriter, r *http.Request) {
	token := r.FormValue("token")
	tokenTypeHint := r.FormValue("token_type_hint")

	// Authenticate the calling client. Per RFC 7009 §2.1, the revocation endpoint MUST be
	// protected against unauthorized callers, so we require a fully authenticated confidential
	// client (client_id + client_secret) rather than the token endpoint's laxer public-client
	// allowance.
	client, err := s.authenticateConfidentialClient(r)
	if err != nil {
		s.writeClientAuthError(w, err)
		return
	}

	if token == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "Token parameter is required")
		return
	}

	// Per RFC 7009, the revocation endpoint should return 200 OK regardless of
	// whether the token was found, already revoked, or belongs to another client.
	// This prevents token enumeration. We attempt to revoke using both methods based on the
	// hint, but per RFC 7009 §2.1 we only actually revoke a token that was issued to the
	// authenticated client — this prevents one client from revoking another client's tokens.

	if tokenTypeHint == "refresh_token" {
		// Try refresh token first, then access token
		s.revokeRefreshTokenIfOwnedByClient(r.Context(), token, client.ID)
		s.revokeAccessTokenIfOwnedByClient(r.Context(), token, client.ID)
	} else {
		// Try access token first (default), then refresh token
		s.revokeAccessTokenIfOwnedByClient(r.Context(), token, client.ID)
		s.revokeRefreshTokenIfOwnedByClient(r.Context(), token, client.ID)
	}

	// Always return 200 OK per RFC 7009
	w.WriteHeader(http.StatusOK)
}

// revokeAccessTokenIfOwnedByClient attempts to revoke an access token, but only if it was
// issued to clientID. For JWTs, the token parameter should be the full JWT. We extract the
// JTI (which is stored in the database) and look up/revoke by that; we also try the raw
// token value in case it's stored differently. If the token isn't found, or belongs to a
// different client, this is a silent no-op — the caller still returns 200 OK per RFC 7009.
func (s *Server) revokeAccessTokenIfOwnedByClient(ctx context.Context, token string, clientID uuid.UUID) {
	// Try to parse as JWT to extract JTI
	if jti := s.extractJTIFromToken(token); jti != "" {
		s.revokeAccessTokenByLookupIfOwned(ctx, jti, clientID)
	}
	// Also try revoking by the raw token value in case it's stored differently
	s.revokeAccessTokenByLookupIfOwned(ctx, token, clientID)
}

// revokeAccessTokenByLookupIfOwned looks up the token record by its stored access_token value
// (which is the JTI for JWTs) and revokes it only if it belongs to clientID.
func (s *Server) revokeAccessTokenByLookupIfOwned(ctx context.Context, accessToken string, clientID uuid.UUID) {
	dbToken, live, err := s.liveAccessToken(ctx, accessToken)
	if err != nil {
		// The lookup failed, so we cannot tell whether this token exists or who
		// owns it, and therefore cannot revoke it. RFC 7009 §2.2 has the
		// endpoint answer 200 regardless, so the caller still does -- but log it,
		// because "revocation returned 200 and silently did nothing" is
		// otherwise invisible.
		log.Printf("revokeAccessTokenByLookupIfOwned: could not look up token to revoke: %v", err)
		return
	}
	if !live {
		// Not found, already revoked, or expired — nothing to do.
		return
	}
	if dbToken.ClientID != clientID {
		// Token belongs to a different client — do not reveal this to the caller, and do not
		// revoke a token this client doesn't own (RFC 7009 §2.1).
		return
	}
	s.datastore.Q.RevokeTokenByAccessToken(ctx, db.RevokeTokenByAccessTokenParams{
		AccessToken: sql.NullString{String: accessToken, Valid: true},
		Reason:      string(revokedRevoked),
	})
}

// revokeRefreshTokenIfOwnedByClient looks up the refresh token and revokes it only if it
// belongs to clientID. If the token isn't found, or belongs to a different client, this is a
// silent no-op — the caller still returns 200 OK per RFC 7009.
func (s *Server) revokeRefreshTokenIfOwnedByClient(ctx context.Context, token string, clientID uuid.UUID) {
	dbToken, err := s.datastore.Q.GetTokenByRefreshToken(ctx, sql.NullString{String: token, Valid: true})
	if err != nil {
		// Not found (or already revoked) — nothing to do.
		return
	}
	if dbToken.ClientID != clientID {
		// Token belongs to a different client — do not revoke it (RFC 7009 §2.1).
		return
	}
	// The row count is intentionally ignored: per RFC 7009 the endpoint returns
	// 200 OK regardless of whether the token was found or already revoked.
	//
	// The reason is "revoked", not "rotated": presenting this token again later
	// is refused, but is not reuse and revokes nothing else.
	_, _ = s.datastore.Q.RevokeTokenByRefreshToken(ctx, db.RevokeTokenByRefreshTokenParams{
		RefreshToken: sql.NullString{String: token, Valid: true},
		Reason:       string(revokedRevoked),
	})
}

// extractJTIFromToken extracts the JTI claim from a JWT without validating it.
// Returns empty string if the token is not a valid JWT or has no JTI.
func (s *Server) extractJTIFromToken(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}

	// Decode the payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}

	var claims struct {
		JTI string `json:"jti"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}

	return claims.JTI
}

// getSessionFromCookie checks if the user is authenticated via session cookie.
// Returns (session, true) if authenticated, (nil Session, false) otherwise.
func (s *Server) getSessionFromCookie(r *http.Request) (Session, error) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return Session{}, fmt.Errorf("failed to get session from cookie: %w", err)
	}

	session, err := s.datastore.Q.GetSession(r.Context(), cookie.Value)
	if err != nil {
		return Session{}, fmt.Errorf("failed to get session from database: %w", err)
	}

	return Session{
		ID:        session.ID,
		UserID:    session.UserID,
		ExpiresAt: session.ExpiresAt,
	}, nil
}

// oauthAuthorizeError describes an OAuth error that should be redirected back to
// the client's redirect_uri per RFC 6749 4.1.2.1.
type oauthAuthorizeError struct {
	Code        string
	Description string
}

// validateAuthorizeParams performs the parameter validation shared by the
// authorize (HandleOauthAuthorize) and consent (HandleConsentPost) endpoints.
// Both endpoints can mint an authorization code, so they must enforce the same
// rules to prevent a validation bypass: response_type must be "code", PKCE
// (code_challenge + S256) is mandatory, and requested scopes must be a subset of
// the client's allowed scopes. Callers must have already validated client_id and
// redirect_uri (so that returned errors can be safely redirected to the client).
// Returns nil when the parameters are valid, otherwise the first failure.
func validateAuthorizeParams(client db.OauthClient, responseType, codeChallenge, codeChallengeMethod string, scope []string) *oauthAuthorizeError {
	if responseType != "code" {
		return &oauthAuthorizeError{"unsupported_response_type", "Only 'code' response type is supported"}
	}
	if codeChallenge == "" || codeChallengeMethod == "" {
		return &oauthAuthorizeError{"invalid_request", "Code challenge and code challenge method are required"}
	}
	if codeChallengeMethod != "S256" {
		return &oauthAuthorizeError{"invalid_request", "Code challenge method must be S256"}
	}
	// offline_access (auth.IsAlwaysGrantableScope) is grantable to every client
	// without registration, so only the remaining scopes are held to
	// allowed_scopes.
	//
	// A metadata-document client has no registered allowed_scopes: what it
	// may ask for is computed from the resource the request resolves to
	// (cimdAllowedScopes), so checkCodeIssuance checks it once that resource
	// is known.
	if client.Kind != clientKindCIMD {
		gatedScopes := slices.DeleteFunc(slices.Clone(scope), auth.IsAlwaysGrantableScope)
		if scopesAllowed, invalidScopes := containsAll(client.AllowedScopes, gatedScopes); !scopesAllowed {
			return &oauthAuthorizeError{"invalid_scope", fmt.Sprintf("Scopes %v not allowed for this client", invalidScopes)}
		}
	}
	// Admin scopes may never ride a user-delegated token.
	//
	// The /admin routes authorize on the scope string alone (see
	// AdminAuthMiddleware): there is no admin flag on auth_users, because roles
	// are deliberately left to downstream apps. Admin authority is therefore a
	// property of the *client*, and the only grant where a client acts as
	// itself is client_credentials -- which handleClientCredentialsGrant already
	// restricts to confidential clients.
	//
	// Without this check the authorization-code flow is a second way in, and a
	// far weaker one. For a public client it is a hole outright: there is no
	// secret to present at the token endpoint, so any user who can reach
	// /oauth/authorize could consent to admin:* and redeem the code themselves
	// with only a client_id and their own PKCE verifier. For a confidential
	// client it is still a hazard, since a user can append admin:* to an
	// authorize request and the resulting token reaches them if the app ever
	// hands access tokens to the browser.
	//
	// Nothing bounded this before: oauth_clients has no grant_types column,
	// HandleOauthToken dispatches on whatever grant_type the request names, and
	// identity-cli will register any scope string against a client that defaults
	// to public. Enforcing the rule here -- shared by authorize and consent, the
	// only two paths that mint an authorization code -- means an over-permissive
	// client registration can no longer become an escalation path.
	//
	// This check sits after the allowed-scopes check on purpose: a client that
	// was never granted admin:* should be told the scope is not allowed for it,
	// which is the more accurate answer.
	if adminScopes := auth.AdminScopesIn(scope); len(adminScopes) > 0 {
		return &oauthAuthorizeError{"invalid_scope", fmt.Sprintf(
			"Scopes %v may only be obtained via the client_credentials grant", adminScopes)}
	}
	return nil
}

// scopeDescriptions maps scope strings to human-readable descriptions.
var scopeDescriptionMap = map[string]string{
	"openid":  "Verify your identity",
	"profile": "View your profile information (name, username, avatar)",
	"email":   "View your email address",
	// Refresh tokens are issued on every code exchange, so this describes
	// what the app gets either way; the scope just lets it say so.
	auth.OfflineAccessScope: "Stay signed in: keep access when you're not using the app",
}

// HandleConsentGet renders the consent page.
//
// Like every page, it is served with X-Frame-Options: DENY and
// Content-Security-Policy: frame-ancestors 'none' (securityHeadersMiddleware),
// which matters most here: a consent screen in an invisible frame is the
// classic clickjacking target.
func (s *Server) HandleConsentGet(w http.ResponseWriter, r *http.Request) {
	request := carriedAuthorizeRequest(r)
	p := request.params()

	// The client and redirect_uri are validated together before anything else,
	// as on the POST: the page names the client and promises where the answer
	// goes, so it must not render for a redirect_uri the client never
	// registered. The POST validates again; this is not a substitute.
	client, err := s.validateOAuthClientRedirect(r.Context(), p.ClientID, p.RedirectURI)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// The page is only rendered for a request the POST would accept, so it
	// runs the same checks (checkCodeIssuance), and gets from them the
	// resource the request resolved to, which the page describes. That also
	// keeps an unknown scope string from ever reaching the page: one is
	// refused here with invalid_scope rather than shown raw.
	//
	// A deactivated account is bounced to login rather than being shown a
	// consent screen it could never submit. This is a rendering courtesy, not
	// the control -- the control is on the POST, where a code could actually
	// be minted.
	grant, denial := s.checkCodeIssuance(r, client, p)
	if denial != nil {
		s.denyCodeIssuance(w, r, denial, codeIssuanceRedirects{
			ToClient: func(errorCode, description string) {
				s.respondWithError(w, r, p, errorCode, description)
			},
			Unauthenticated: request.loginURL(nil),
			Deactivated:     request.loginURL(url.Values{"error": {"account_deactivated"}}),
		})
		return
	}

	// A trusted client has no consent screen. The authorize endpoint never
	// sends one here, but a request that arrives anyway (an old link, a
	// hand-typed URL) goes back to authorize, which issues the code after the
	// same checks.
	if client.Trusted {
		http.Redirect(w, r, request.authorizeURL(), http.StatusFound)
		return
	}

	data := consentView(client, p, grant.Resource)
	data.AuthorizeQuery = string(request)
	data.CSRFToken = s.ensureCSRFToken(w, r)

	if err := views.Consent(data).Render(r.Context(), w); err != nil {
		http.Error(w, "An error occurred", http.StatusInternalServerError)
	}
}

// HandleConsentPost processes the consent decision.
func (s *Server) HandleConsentPost(w http.ResponseWriter, r *http.Request) {
	decision := r.FormValue("decision")
	// The authorization request the consent page carried. It came back through
	// a form the user controls, so it is re-validated below exactly as
	// /oauth/authorize validates a request that arrives directly.
	request := carriedAuthorizeRequest(r)
	p := request.params()

	// Validate the client and redirect URI
	client, err := s.validateOAuthClientRedirect(r.Context(), p.ClientID, p.RedirectURI)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Helper to redirect errors to the client
	redirectError := func(errorCode, description string) {
		s.respondWithError(w, r, p, errorCode, description)
	}

	// The same preconditions the authorize endpoint enforces, from the same
	// place. Without this, a user could POST directly to /oauth/consent and
	// bypass whatever HandleOauthAuthorize checks -- which is exactly how these
	// two drifted before (a PKCE-less code with arbitrary scopes, and later a
	// deactivated user obtaining a code). See code_issuance.go.
	// A refusal is answered before anything else. Declining consent mints no
	// code, so the preconditions for minting one have no business gating it --
	// and the client is entitled to be told the user said no regardless of the
	// state of their account. Checking first would silently swallow the refusal
	// of, say, a deactivated user and leave the client waiting.
	if decision == "deny" {
		redirectError("access_denied", "User denied consent")
		return
	}

	// Re-entering /oauth/authorize is how a user who cannot proceed here is
	// routed onward: it sends them to login carrying the authorization request,
	// so once they can proceed they land back at the app instead of being
	// stranded on the account page. The deactivated case goes straight to login
	// with the error that tells the page what to say.
	grant, denial := s.checkCodeIssuance(r, client, p)
	if denial != nil {
		s.denyCodeIssuance(w, r, denial, codeIssuanceRedirects{
			ToClient:        redirectError,
			Unauthenticated: request.authorizeURL(),
			Deactivated:     request.loginURL(url.Values{"error": {"account_deactivated"}}),
		})
		return
	}
	session := grant.Session

	// Store consent, for this resource only. Never for a trusted client:
	// its consent is implied, and a row would only be noise (the Connected
	// Apps page ignores it anyway). A POST for one is not reachable from the
	// screen, which a trusted client never gets, but is harmless: the checks
	// above are the authorize endpoint's.
	if !client.Trusted {
		err = s.datastore.Q.UpsertUserConsent(r.Context(), db.UpsertUserConsentParams{
			UserID:   session.UserID,
			ClientID: client.ID,
			Resource: grant.Resource.uri(),
			Scopes:   p.Scope,
		})
		if err != nil {
			log.Printf("HandleConsentPost: failed to store consent: %v", err)
			redirectError("server_error", "Failed to store consent")
			return
		}
	}

	// Generate authorization code and redirect to client
	authorizationCode, err := s.generateAuthorizationCode(r.Context(), session.UserID, client.ID, p.RedirectURI, p.Scope, p.CodeChallenge, p.CodeChallengeMethod, p.Nonce, grant.Resource.uri())
	if err != nil {
		redirectError("server_error", "An error occurred")
		return
	}
	s.respondWithCode(w, r, p, authorizationCode)
}
