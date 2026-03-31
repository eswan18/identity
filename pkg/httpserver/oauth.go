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

	"github.com/eswan18/identity/pkg/db"
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
// @Description  Validates OAuth2 parameters, checks if user is authenticated (via session cookie), renders login page if not authenticated, or generates authorization code and redirects to redirect_uri if authenticated
// @Tags         oauth2
// @Produce      html
// @Param        response_type        query     string  true  "Must be 'code'"
// @Param        client_id            query     string  true  "Registered client identifier"
// @Param        redirect_uri        query     string  true  "Where to send the user after auth"
// @Param        scope               query     string  false "Requested scopes (e.g., 'openid profile email'). Defaults to 'openid' if not provided."
// @Param        state               query     string  false "CSRF protection token. Recommended for OAuth flow."
// @Param        code_challenge      query     string  false "PKCE code challenge (SHA256 hash). Required for OAuth flow."
// @Param        code_challenge_method query   string  false "PKCE challenge method (must be 'S256'). Required for OAuth flow."
// @Success      302 {string} string "Redirect to redirect_uri with authorization code and state"
// @Failure      302 {string} string "Redirect to redirect_uri with error parameters"
// @Router       /oauth/authorize [get]
func (s *Server) HandleOauthAuthorize(w http.ResponseWriter, r *http.Request) {
	responseType := r.URL.Query().Get("response_type")
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	scopeParam := r.URL.Query().Get("scope")
	var scope []string
	if scopeParam == "" {
		scope = []string{"openid"}
	} else {
		scope = strings.Split(scopeParam, " ")
	}
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")
	state := r.URL.Query().Get("state")
	nonce := r.URL.Query().Get("nonce")

	// Phase 1: Validate client_id and redirect_uri first.
	// Per RFC 6749 4.1.2.1, if these are invalid we MUST NOT redirect — show error directly.
	if clientID == "" {
		http.Error(w, "Client ID is required", http.StatusBadRequest)
		return
	}
	if redirectURI == "" {
		http.Error(w, "Redirect URI is required", http.StatusBadRequest)
		return
	}
	client, err := s.validateOAuthClientRedirect(r.Context(), clientID, redirectURI)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// redirectError is a helper that redirects OAuth errors to the client per RFC 6749 4.1.2.1.
	// Only safe to use after client_id and redirect_uri have been validated above.
	redirectError := func(errorCode, description string) {
		redirectURL, _ := url.Parse(redirectURI)
		q := redirectURL.Query()
		q.Set("error", errorCode)
		q.Set("error_description", description)
		q.Set("state", state)
		redirectURL.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURL.String(), http.StatusFound)
	}

	// Phase 2: Validate remaining parameters. These errors are redirected to the client.
	if responseType != "code" {
		redirectError("unsupported_response_type", "Only 'code' response type is supported")
		return
	}
	if codeChallenge == "" || codeChallengeMethod == "" {
		redirectError("invalid_request", "Code challenge and code challenge method are required")
		return
	}
	if codeChallengeMethod != "S256" {
		redirectError("invalid_request", "Code challenge method must be S256")
		return
	}

	// Validate scopes against client's allowed scopes
	if scopesAllowed, invalidScopes := containsAll(client.AllowedScopes, scope); !scopesAllowed {
		redirectError("invalid_scope", fmt.Sprintf("Scopes %v not allowed for this client", invalidScopes))
		return
	}

	// Phase 3: Check authentication and user status.
	session, err := s.getSessionFromCookie(r)
	if err != nil {
		// If not authenticated, redirect to login page with OAuth parameters preserved
		loginURL := "/oauth/login?" + r.URL.RawQuery
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	user, err := s.datastore.Q.GetUserByIDIncludingInactive(r.Context(), session.UserID)
	if err != nil {
		redirectError("server_error", "An error occurred")
		return
	}
	if !user.IsActive {
		loginURL := "/oauth/login?error=account_deactivated&" + r.URL.RawQuery
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// Phase 4: Check consent. If user hasn't consented to these scopes, redirect to consent page.
	consent, err := s.datastore.Q.GetUserConsent(r.Context(), db.GetUserConsentParams{
		UserID:   session.UserID,
		ClientID: client.ID,
	})
	if err != nil || !scopesCovered(consent.Scopes, scope) {
		// Need consent — redirect to consent page with all OAuth params
		consentURL := "/oauth/consent?" + r.URL.RawQuery
		http.Redirect(w, r, consentURL, http.StatusFound)
		return
	}

	// Phase 5: Generate authorization code and redirect.
	authorizationCode, err := s.generateAuthorizationCode(r.Context(), session.UserID, client.ID, redirectURI, scope, codeChallenge, codeChallengeMethod, nonce)
	if err != nil {
		redirectError("server_error", "An error occurred")
		return
	}
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "Invalid redirect URI", http.StatusBadRequest)
		return
	}
	q := redirectURL.Query()
	q.Set("code", authorizationCode)
	q.Set("state", state)
	redirectURL.RawQuery = q.Encode()
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
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
// @Success      200 {object} map[string]interface{} "Token response with access_token, token_type, expires_in, refresh_token, scope, and id_token (when openid scope requested)"
// @Failure      400 {object} map[string]string "OAuth2 error response (invalid_request, invalid_grant, invalid_client, etc.)"
// @Router       /oauth/token [post]
func (s *Server) HandleOauthToken(w http.ResponseWriter, r *http.Request) {
	grantType := r.FormValue("grant_type")

	client, err := s.authenticateClient(r)
	if err != nil {
		s.writeTokenError(w, "invalid_client", "Invalid client credentials")
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

// handleOauthRefresh godoc
// @Summary      OAuth2 refresh token endpoint
// @Description  Exchanges a refresh token for new access and refresh tokens
// @Tags         oauth2
// @Accept       application/x-www-form-urlencoded
// @Produce      json
// @Param        refresh_token formData  string  true  "Refresh token to exchange"
// @Param        client_id     formData  string  true  "OAuth client ID"
// @Param        client_secret formData  string  false "OAuth client secret (required for confidential clients)"
// @Success      200 {object} TokenResponse "Token response with access_token, token_type, expires_in, refresh_token, and scope"
// @Failure      400 {object} map[string]string "OAuth2 error response (invalid_request, invalid_grant, invalid_client, etc.)"
// @Router       /oauth/refresh [post]
func (s *Server) HandleOauthRefresh(w http.ResponseWriter, r *http.Request) {
	client, err := s.authenticateClient(r)
	if err != nil {
		s.writeTokenError(w, "invalid_client", "Invalid client credentials")
		return
	}

	s.handleRefreshTokenGrant(w, r, client)
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
		s.writeTokenError(w, "invalid_grant", "Invalid authorization code")
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

	// Verify PKCE code_verifier
	if authCode.CodeChallenge.Valid {
		if codeVerifier == "" {
			s.writeTokenError(w, "invalid_request", "Code verifier is required")
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

	// Mark the authorization code as consumed
	err = s.datastore.Q.ConsumeAuthorizationCode(r.Context(), code)
	if err != nil {
		s.writeTokenError(w, "server_error", "Failed to consume authorization code")
		return
	}

	// Generate tokens, passing nonce for inclusion in the ID token
	nonce := ""
	if authCode.Nonce.Valid {
		nonce = authCode.Nonce.String
	}
	s.writeTokenResponse(w, r, client.ID, authCode.UserID, authCode.Scope, nonce)
}

// handleRefreshTokenGrant exchanges a refresh token for new tokens
func (s *Server) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, client db.OauthClient) {
	refreshToken := r.FormValue("refresh_token")

	if refreshToken == "" {
		s.writeTokenError(w, "invalid_request", "Refresh token is required")
		return
	}

	// Look up the token by refresh token
	token, err := s.datastore.Q.GetTokenByRefreshToken(r.Context(), sql.NullString{String: refreshToken, Valid: true})
	if err != nil {
		s.writeTokenError(w, "invalid_grant", "Invalid refresh token")
		return
	}

	// Validate the client ID matches
	if token.ClientID != client.ID {
		s.writeTokenError(w, "invalid_grant", "Refresh token was not issued to this client")
		return
	}

	// Check if refresh token has expired
	if token.RefreshExpiresAt.Valid && token.RefreshExpiresAt.Time.Before(time.Now()) {
		s.writeTokenError(w, "invalid_grant", "Refresh token has expired")
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

	// Revoke the old token
	err = s.datastore.Q.RevokeTokenByRefreshToken(r.Context(), sql.NullString{String: refreshToken, Valid: true})
	if err != nil {
		s.writeTokenError(w, "server_error", "Failed to revoke old token")
		return
	}

	// Issue new tokens with the same user and scope (no nonce on refresh)
	var userID uuid.UUID
	if token.UserID.Valid {
		userID = token.UserID.UUID
	}
	s.writeTokenResponse(w, r, client.ID, userID, token.Scope, "")
}

// writeTokenResponse generates tokens and writes the JSON response.
// nonce is included in the ID token if non-empty (per OIDC Core 3.1.2.1).
func (s *Server) writeTokenResponse(w http.ResponseWriter, r *http.Request, clientID uuid.UUID, userID uuid.UUID, scope []string, nonce string) {
	tokens, err := s.generateTokens(r.Context(), clientID, userID, scope, nonce)
	if err != nil {
		s.writeTokenError(w, "server_error", "Failed to generate tokens")
		return
	}

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
	// Client credentials grant requires a confidential client
	if !client.IsConfidential {
		s.writeTokenError(w, "unauthorized_client", "Client credentials grant requires a confidential client")
		return
	}

	// Parse requested scopes (optional, defaults to all allowed scopes)
	scopeParam := r.FormValue("scope")
	var requestedScopes []string
	if scopeParam == "" {
		requestedScopes = client.AllowedScopes
	} else {
		requestedScopes = strings.Split(scopeParam, " ")
	}

	// Validate requested scopes against client's allowed_scopes
	if allowed, invalidScopes := containsAll(client.AllowedScopes, requestedScopes); !allowed {
		s.writeTokenError(w, "invalid_scope", fmt.Sprintf("Scopes %v not allowed for this client", invalidScopes))
		return
	}

	// Generate service account token (no user, no refresh token)
	s.writeClientCredentialsTokenResponse(w, r, client, requestedScopes)
}

// writeClientCredentialsTokenResponse generates service account tokens and writes the JSON response.
// Per OAuth2 spec, client_credentials does not include a refresh token.
func (s *Server) writeClientCredentialsTokenResponse(w http.ResponseWriter, r *http.Request, client db.OauthClient, scope []string) {
	tokens, err := s.generateServiceAccountTokens(r.Context(), client.ID, scope)
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

// writeTokenError writes an OAuth2 error response with 400 status
func (s *Server) writeTokenError(w http.ResponseWriter, errorCode, description string) {
	writeJSONError(w, http.StatusBadRequest, errorCode, description)
}

// handleUserInfo godoc
// @Summary      OIDC UserInfo endpoint
// @Description  Returns user identity claims for the authenticated user. Claims are gated by scope per OIDC Core Section 5.4: "sub" is always returned; "email" and "email_verified" require the "email" scope; "username", "given_name", "family_name", and "picture" require the "profile" scope.
// @Tags         oidc
// @Produce      json
// @Security     BearerAuth
// @Param        Authorization header string true "Bearer access token"
// @Success      200 {object} map[string]interface{} "User identity claims (scope-dependent)"
// @Failure      401 {object} map[string]string "Unauthorized - invalid or missing access token"
// @Router       /oauth/userinfo [get]
func (s *Server) HandleOauthUserInfo(w http.ResponseWriter, r *http.Request) {
	// Extract Bearer token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_token",
			"error_description": "Missing or invalid Authorization header",
		})
		return
	}

	accessToken := strings.TrimPrefix(authHeader, "Bearer ")

	// Validate the JWT and extract claims
	// Note: We don't validate audience here since this is the identity provider's own endpoint.
	// Audience validation is done by resource servers (like the fitness API).
	claims, err := s.jwtGenerator.ValidateToken(accessToken, "")
	if err != nil {
		// Log the detailed error server-side, but return generic error to client
		// to avoid leaking information about token structure or validation logic
		log.Printf("JWT validation failed: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_token",
			"error_description": "Invalid or expired access token",
		})
		return
	}

	// Check if token has been revoked by looking up the JTI
	if claims.ID != "" {
		token, err := s.datastore.Q.GetTokenByAccessToken(r.Context(), sql.NullString{String: claims.ID, Valid: true})
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				// Database error (not "not found") - fail closed for security
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{
					"error":             "server_error",
					"error_description": "Failed to verify token status",
				})
				return
			}
			// Token not found in DB - that's okay, JWT is still valid
			// This can happen if revocation tracking is not enabled
		} else if token.RevokedAt.Valid {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error":             "invalid_token",
				"error_description": "Token has been revoked",
			})
			return
		}
	}

	// Return OIDC standard claims from JWT.
	// Only "sub" is always included; other claims are gated by scope per OIDC Core Section 5.4.
	userInfo := map[string]interface{}{
		"sub": claims.Subject,
	}

	// "email" scope: email and email_verified
	scopes := strings.Split(claims.Scope, " ")
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

	// Authenticate the calling client
	_, err := s.authenticateClient(r)
	if err != nil {
		s.writeIntrospectError(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials")
		return
	}

	if token == "" {
		s.writeIntrospectError(w, http.StatusBadRequest, "invalid_request", "Token parameter is required")
		return
	}

	// Try to introspect based on hint, or try both if no hint
	var response map[string]interface{}

	if tokenTypeHint == "refresh_token" {
		response = s.introspectRefreshToken(r.Context(), token)
	} else if tokenTypeHint == "access_token" || tokenTypeHint == "" {
		// Try access token first
		var err error
		response, err = s.introspectAccessToken(r.Context(), token)
		if err != nil {
			log.Printf("HandleIntrospect: %v", err)
			s.writeIntrospectError(w, http.StatusInternalServerError, "server_error", "Failed to verify token status")
			return
		}
		// If not active and no hint was provided, try refresh token
		if !response["active"].(bool) && tokenTypeHint == "" {
			response = s.introspectRefreshToken(r.Context(), token)
		}
	} else {
		// Unknown hint, try both
		var err error
		response, err = s.introspectAccessToken(r.Context(), token)
		if err != nil {
			log.Printf("HandleIntrospect: %v", err)
			s.writeIntrospectError(w, http.StatusInternalServerError, "server_error", "Failed to verify token status")
			return
		}
		if !response["active"].(bool) {
			response = s.introspectRefreshToken(r.Context(), token)
		}
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
	dbToken, err := s.datastore.Q.GetTokenByAccessToken(ctx, sql.NullString{String: claims.ID, Valid: true})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Token not found in DB — treat as inactive
			return inactive, nil
		}
		// Database error — report to caller so it can return a server error
		return nil, fmt.Errorf("introspectAccessToken: database error: %w", err)
	}

	// Token is valid and not revoked
	response := map[string]interface{}{
		"active":     true,
		"scope":      claims.Scope,
		"client_id":  dbToken.ClientID.String(),
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

// introspectRefreshToken attempts to introspect a refresh token
func (s *Server) introspectRefreshToken(ctx context.Context, token string) map[string]interface{} {
	dbToken, err := s.datastore.Q.GetTokenByRefreshToken(ctx, sql.NullString{String: token, Valid: true})
	if err != nil {
		return map[string]interface{}{"active": false}
	}

	// Check if refresh token is expired
	if dbToken.RefreshExpiresAt.Valid && dbToken.RefreshExpiresAt.Time.Before(time.Now()) {
		return map[string]interface{}{"active": false}
	}

	// Get user info for the response
	user, err := s.datastore.Q.GetUserByID(ctx, dbToken.UserID.UUID)
	username := ""
	if err == nil {
		username = user.Username
	}

	return map[string]interface{}{
		"active":     true,
		"scope":      strings.Join(dbToken.Scope, " "),
		"client_id":  dbToken.ClientID.String(),
		"username":   username,
		"token_type": "refresh_token",
		"exp":        dbToken.RefreshExpiresAt.Time.Unix(),
		"iat":        dbToken.CreatedAt.Unix(),
		"sub":        dbToken.UserID.UUID.String(),
	}
}

// writeIntrospectError writes an error response for the introspection endpoint
func (s *Server) writeIntrospectError(w http.ResponseWriter, statusCode int, errorCode, description string) {
	writeJSONError(w, statusCode, errorCode, description)
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

	// Authenticate the calling client
	_, err := s.authenticateClient(r)
	if err != nil {
		s.writeRevokeError(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials")
		return
	}

	if token == "" {
		s.writeRevokeError(w, http.StatusBadRequest, "invalid_request", "Token parameter is required")
		return
	}

	// Per RFC 7009, the revocation endpoint should return 200 OK regardless of
	// whether the token was found or already revoked. This prevents token enumeration.
	// We attempt to revoke using both methods based on the hint.

	if tokenTypeHint == "refresh_token" {
		// Try refresh token first, then access token
		s.datastore.Q.RevokeTokenByRefreshToken(r.Context(), sql.NullString{String: token, Valid: true})
		s.revokeAccessToken(r.Context(), token)
	} else {
		// Try access token first (default), then refresh token
		s.revokeAccessToken(r.Context(), token)
		s.datastore.Q.RevokeTokenByRefreshToken(r.Context(), sql.NullString{String: token, Valid: true})
	}

	// Always return 200 OK per RFC 7009
	w.WriteHeader(http.StatusOK)
}

// revokeAccessToken attempts to revoke an access token.
// For JWTs, the token parameter should be the full JWT. We extract the JTI
// (which is stored in the database) and revoke by that.
func (s *Server) revokeAccessToken(ctx context.Context, token string) {
	// Try to parse as JWT to extract JTI
	jti := s.extractJTIFromToken(token)
	if jti != "" {
		s.datastore.Q.RevokeTokenByAccessToken(ctx, sql.NullString{String: jti, Valid: true})
	}
	// Also try revoking by the raw token value in case it's stored differently
	s.datastore.Q.RevokeTokenByAccessToken(ctx, sql.NullString{String: token, Valid: true})
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

// writeRevokeError writes an error response for the revocation endpoint
func (s *Server) writeRevokeError(w http.ResponseWriter, statusCode int, errorCode, description string) {
	writeJSONError(w, statusCode, errorCode, description)
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

// HandleOIDCDiscovery godoc
// @Summary      OIDC Discovery endpoint
// @Description  Returns OpenID Connect Provider Configuration (RFC 8414). Allows clients to discover all necessary endpoints and provider capabilities.
// @Tags         oauth2
// @Produce      json
// @Success      200 {object} map[string]interface{} "OIDC provider configuration"
// @Router       /.well-known/openid-configuration [get]
func (s *Server) HandleOIDCDiscovery(w http.ResponseWriter, r *http.Request) {
	issuer := s.config.JWTIssuer

	discovery := map[string]interface{}{
		// Required fields per OpenID Connect Discovery 1.0
		"issuer":                 issuer,
		"authorization_endpoint": issuer + "/oauth/authorize",
		"token_endpoint":         issuer + "/oauth/token",
		"jwks_uri":               issuer + "/.well-known/jwks.json",

		// Recommended fields
		"userinfo_endpoint":                   issuer + "/oauth/userinfo",
		"scopes_supported":                    []string{"openid", "profile", "email"},
		"response_types_supported":            []string{"code"},
		"response_modes_supported":            []string{"query"},
		"grant_types_supported":               []string{"authorization_code", "refresh_token", "client_credentials"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
		"subject_types_supported":             []string{"public"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "iat", "at_hash",
			"email", "email_verified",
			"preferred_username", "given_name", "family_name", "picture",
		},
		"code_challenge_methods_supported": []string{"S256"},

		// Additional endpoints
		"introspection_endpoint": issuer + "/oauth/introspect",
		"revocation_endpoint":    issuer + "/oauth/revoke",
		"end_session_endpoint":   issuer + "/oauth/logout",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(discovery)
}

// scopesCovered returns true if all requested scopes are present in the stored scopes.
func scopesCovered(storedScopes, requestedScopes []string) bool {
	for _, s := range requestedScopes {
		if !slices.Contains(storedScopes, s) {
			return false
		}
	}
	return true
}

// scopeDescriptions maps scope strings to human-readable descriptions.
var scopeDescriptionMap = map[string]string{
	"openid":  "Verify your identity",
	"profile": "View your profile information (name, username, avatar)",
	"email":   "View your email address",
}

// HandleConsentGet renders the consent page.
func (s *Server) HandleConsentGet(w http.ResponseWriter, r *http.Request) {
	// Verify session
	session, err := s.getSessionFromCookie(r)
	if err != nil {
		http.Redirect(w, r, "/oauth/login?"+r.URL.RawQuery, http.StatusFound)
		return
	}
	_ = session

	clientID := r.URL.Query().Get("client_id")
	scopeParam := r.URL.Query().Get("scope")
	var scope []string
	if scopeParam == "" {
		scope = []string{"openid"}
	} else {
		scope = strings.Split(scopeParam, " ")
	}

	// Look up client name
	client, err := s.datastore.Q.GetOAuthClientByClientID(r.Context(), clientID)
	if err != nil {
		http.Error(w, "Invalid client", http.StatusBadRequest)
		return
	}

	// Build scope descriptions
	var descriptions []ScopeDescription
	for _, sc := range scope {
		desc, ok := scopeDescriptionMap[sc]
		if ok {
			descriptions = append(descriptions, ScopeDescription{Scope: sc, Description: desc})
		} else {
			descriptions = append(descriptions, ScopeDescription{Scope: sc, Description: sc})
		}
	}

	data := ConsentPageData{
		ClientName:          client.Name,
		ClientID:            clientID,
		RedirectURI:         r.URL.Query().Get("redirect_uri"),
		State:               r.URL.Query().Get("state"),
		Scope:               scope,
		ScopeDescriptions:   descriptions,
		CodeChallenge:       r.URL.Query().Get("code_challenge"),
		CodeChallengeMethod: r.URL.Query().Get("code_challenge_method"),
		Nonce:               r.URL.Query().Get("nonce"),
		ResponseType:        r.URL.Query().Get("response_type"),
	}

	if err := s.consentTemplate.Execute(w, data); err != nil {
		http.Error(w, "An error occurred", http.StatusInternalServerError)
	}
}

// HandleConsentPost processes the consent decision.
func (s *Server) HandleConsentPost(w http.ResponseWriter, r *http.Request) {
	session, err := s.getSessionFromCookie(r)
	if err != nil {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	decision := r.FormValue("decision")
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")
	scopeParam := r.FormValue("scope")
	var scope []string
	if scopeParam == "" {
		scope = []string{"openid"}
	} else {
		scope = strings.Split(scopeParam, " ")
	}
	codeChallenge := r.FormValue("code_challenge")
	codeChallengeMethod := r.FormValue("code_challenge_method")
	nonce := r.FormValue("nonce")

	// Validate the client and redirect URI
	client, err := s.validateOAuthClientRedirect(r.Context(), clientID, redirectURI)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Helper to redirect errors to the client
	redirectError := func(errorCode, description string) {
		redirectURL, _ := url.Parse(redirectURI)
		q := redirectURL.Query()
		q.Set("error", errorCode)
		q.Set("error_description", description)
		q.Set("state", state)
		redirectURL.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURL.String(), http.StatusFound)
	}

	if decision == "deny" {
		redirectError("access_denied", "User denied consent")
		return
	}

	// Store consent
	err = s.datastore.Q.UpsertUserConsent(r.Context(), db.UpsertUserConsentParams{
		UserID:   session.UserID,
		ClientID: client.ID,
		Scopes:   scope,
	})
	if err != nil {
		log.Printf("HandleConsentPost: failed to store consent: %v", err)
		redirectError("server_error", "Failed to store consent")
		return
	}

	// Generate authorization code and redirect to client
	authorizationCode, err := s.generateAuthorizationCode(r.Context(), session.UserID, client.ID, redirectURI, scope, codeChallenge, codeChallengeMethod, nonce)
	if err != nil {
		redirectError("server_error", "An error occurred")
		return
	}

	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "Invalid redirect URI", http.StatusBadRequest)
		return
	}
	q := redirectURL.Query()
	q.Set("code", authorizationCode)
	q.Set("state", state)
	redirectURL.RawQuery = q.Encode()
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}
