package httpserver

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
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

	if responseType != "code" {
		http.Error(w, "Invalid response type", http.StatusBadRequest)
		return
	}
	if clientID == "" {
		http.Error(w, "Client ID is required", http.StatusBadRequest)
		return
	}
	if redirectURI == "" {
		http.Error(w, "Redirect URI is required", http.StatusBadRequest)
		return
	}
	if codeChallenge == "" {
		http.Error(w, "Code challenge is required", http.StatusBadRequest)
		return
	}
	if codeChallengeMethod == "" {
		http.Error(w, "Code challenge method is required", http.StatusBadRequest)
		return
	}
	if codeChallengeMethod != "S256" {
		http.Error(w, "Invalid code challenge method", http.StatusBadRequest)
		return
	}

	// Check if user is authenticated via session cookie
	session, err := s.getSessionFromCookie(r)
	if err != nil {
		// If not authenticated, redirect to login page with OAuth parameters preserved -- just pull the whole query string
		loginURL := "/oauth/login?" + r.URL.RawQuery
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// Check if the user is deactivated - they should not be able to authorize OAuth clients
	user, err := s.datastore.Q.GetUserByIDIncludingInactive(r.Context(), session.UserID)
	if err != nil {
		http.Error(w, "An error occurred", http.StatusInternalServerError)
		return
	}
	if !user.IsActive {
		// Deactivated users cannot authorize OAuth clients
		// Redirect to login page with error message
		loginURL := "/oauth/login?error=account_deactivated&" + r.URL.RawQuery
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	client, err := s.validateOAuthClient(r.Context(), clientID, redirectURI, scope)
	if err != nil {
		// All OAuth client validation errors are 400 Bad Request
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// generate authorization code and redirect to redirect_uri
	authorizationCode, err := s.generateAuthorizationCode(r.Context(), session.UserID, client.ID, redirectURI, scope, codeChallenge, codeChallengeMethod)
	if err != nil {
		http.Error(w, "An error occurred", http.StatusInternalServerError)
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
// @Success      200 {object} map[string]interface{} "Token response with access_token, token_type, expires_in, refresh_token, id_token, and scope"
// @Failure      400 {object} map[string]string "OAuth2 error response (invalid_request, invalid_grant, invalid_client, etc.)"
// @Router       /oauth/token [post]
func (s *Server) HandleOauthToken(w http.ResponseWriter, r *http.Request) {
	grantType := r.FormValue("grant_type")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	// Validate client credentials
	client, err := s.datastore.Q.GetOAuthClientByClientID(r.Context(), clientID)
	if err != nil {
		s.writeTokenError(w, "invalid_client", "Invalid client credentials")
		return
	}

	// For confidential clients, verify client secret
	if client.IsConfidential {
		if !client.ClientSecret.Valid || subtle.ConstantTimeCompare([]byte(client.ClientSecret.String), []byte(clientSecret)) != 1 {
			s.writeTokenError(w, "invalid_client", "Invalid client credentials")
			return
		}
	}

	switch grantType {
	case "authorization_code":
		s.handleAuthorizationCodeGrant(w, r, client)
	case "refresh_token":
		s.handleRefreshTokenGrant(w, r, client)
	default:
		s.writeTokenError(w, "unsupported_grant_type", "Grant type must be 'authorization_code' or 'refresh_token'")
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
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	// Validate client credentials
	client, err := s.datastore.Q.GetOAuthClientByClientID(r.Context(), clientID)
	if err != nil {
		s.writeTokenError(w, "invalid_client", "Invalid client credentials")
		return
	}

	// For confidential clients, verify client secret
	if client.IsConfidential {
		if !client.ClientSecret.Valid || subtle.ConstantTimeCompare([]byte(client.ClientSecret.String), []byte(clientSecret)) != 1 {
			s.writeTokenError(w, "invalid_client", "Invalid client credentials")
			return
		}
	}

	// Handle the refresh token grant
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

	// Generate tokens
	s.writeTokenResponse(w, r, client.ID, authCode.UserID, authCode.Scope)
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

	// Issue new tokens with the same user and scope
	var userID uuid.UUID
	if token.UserID.Valid {
		userID = token.UserID.UUID
	}
	s.writeTokenResponse(w, r, client.ID, userID, token.Scope)
}

// writeTokenResponse generates tokens and writes the JSON response
func (s *Server) writeTokenResponse(w http.ResponseWriter, r *http.Request, clientID uuid.UUID, userID uuid.UUID, scope []string) {
	tokens, err := s.generateTokens(r.Context(), clientID, userID, scope)
	if err != nil {
		s.writeTokenError(w, "server_error", "Failed to generate tokens")
		return
	}

	response := TokenResponse{
		AccessToken:  tokens.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    tokens.ExpiresIn,
		RefreshToken: tokens.RefreshToken,
		Scope:        strings.Join(tokens.Scope, " "),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(response)
}

// writeTokenError writes an OAuth2 error response
func (s *Server) writeTokenError(w http.ResponseWriter, errorCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             errorCode,
		"error_description": description,
	})
}

// handleUserInfo godoc
// @Summary      OIDC UserInfo endpoint
// @Description  Returns user profile claims (sub, username, email, email_verified) for the authenticated user. This endpoint provides user identity information, not token metadata.
// @Tags         oidc
// @Produce      json
// @Security     BearerAuth
// @Param        Authorization header string true "Bearer access token"
// @Success      200 {object} map[string]interface{} "User profile claims (sub, username, email, email_verified)"
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

	// Return OIDC standard claims from JWT
	userInfo := map[string]interface{}{
		"sub":            claims.Subject,  // Subject (user ID)
		"username":       claims.Username,
		"email":          claims.Email,
		"email_verified": true, // JWT was issued after authentication
	}

	// Include scope-specific claims
	if strings.Contains(claims.Scope, "profile") {
		// For profile scope, we'd need to fetch from DB for updated_at
		// Skip for now since JWT doesn't contain this claim
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
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	token := r.FormValue("token")
	tokenTypeHint := r.FormValue("token_type_hint")

	// Authenticate the calling client
	client, err := s.datastore.Q.GetOAuthClientByClientID(r.Context(), clientID)
	if err != nil {
		s.writeIntrospectError(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials")
		return
	}

	// For confidential clients, verify client secret
	if client.IsConfidential {
		if !client.ClientSecret.Valid || subtle.ConstantTimeCompare([]byte(client.ClientSecret.String), []byte(clientSecret)) != 1 {
			s.writeIntrospectError(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials")
			return
		}
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
		response = s.introspectAccessToken(r.Context(), token)
		// If not active and no hint was provided, try refresh token
		if !response["active"].(bool) && tokenTypeHint == "" {
			response = s.introspectRefreshToken(r.Context(), token)
		}
	} else {
		// Unknown hint, try both
		response = s.introspectAccessToken(r.Context(), token)
		if !response["active"].(bool) {
			response = s.introspectRefreshToken(r.Context(), token)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// introspectAccessToken attempts to introspect a JWT access token
func (s *Server) introspectAccessToken(ctx context.Context, token string) map[string]interface{} {
	// Parse the JWT without audience validation (resource server may have different audience)
	claims, err := s.jwtGenerator.ValidateToken(token, "")
	if err != nil {
		return map[string]interface{}{"active": false}
	}

	// Check if the token has been revoked by looking up the JTI
	dbToken, err := s.datastore.Q.GetTokenByAccessToken(ctx, sql.NullString{String: claims.ID, Valid: true})
	if err != nil {
		// Token not found in DB or revoked
		return map[string]interface{}{"active": false}
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

	return response
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
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             errorCode,
		"error_description": description,
	})
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
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	token := r.FormValue("token")
	tokenTypeHint := r.FormValue("token_type_hint")

	// Authenticate the calling client
	client, err := s.datastore.Q.GetOAuthClientByClientID(r.Context(), clientID)
	if err != nil {
		s.writeRevokeError(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials")
		return
	}

	// For confidential clients, verify client secret
	if client.IsConfidential {
		if !client.ClientSecret.Valid || subtle.ConstantTimeCompare([]byte(client.ClientSecret.String), []byte(clientSecret)) != 1 {
			s.writeRevokeError(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials")
			return
		}
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
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             errorCode,
		"error_description": description,
	})
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
		"registration_endpoint":               issuer + "/oauth/register",
		"scopes_supported":                    []string{"openid", "profile", "email"},
		"response_types_supported":            []string{"code"},
		"response_modes_supported":            []string{"query"},
		"grant_types_supported":               []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
		"subject_types_supported":             []string{"public"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "iat", "name", "email", "email_verified",
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
