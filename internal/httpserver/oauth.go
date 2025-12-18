package httpserver

import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/eswan18/identity/internal/db"
	"github.com/google/uuid"
)

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
func (s *Server) handleOauthAuthorize(w http.ResponseWriter, r *http.Request) {
	responseType := r.URL.Query().Get("response_type")
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	scope := strings.Split(r.URL.Query().Get("scope"), " ")
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
	if len(scope) == 0 {
		scope = []string{"openid"}
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
func (s *Server) handleOauthToken(w http.ResponseWriter, r *http.Request) {
	grantType := r.FormValue("grant_type")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	// Validate client credentials
	client, err := s.datastore.Q.GetOAuthClientByClientID(r.Context(), clientID)
	if err != nil {
		s.tokenError(w, "invalid_client", "Invalid client credentials")
		return
	}

	// For confidential clients, verify client secret
	if client.IsConfidential {
		if !client.ClientSecret.Valid || subtle.ConstantTimeCompare([]byte(client.ClientSecret.String), []byte(clientSecret)) != 1 {
			s.tokenError(w, "invalid_client", "Invalid client credentials")
			return
		}
	}

	switch grantType {
	case "authorization_code":
		s.handleAuthorizationCodeGrant(w, r, client)
	case "refresh_token":
		s.handleRefreshTokenGrant(w, r, client)
	default:
		s.tokenError(w, "unsupported_grant_type", "Grant type must be 'authorization_code' or 'refresh_token'")
	}
}

// handleAuthorizationCodeGrant exchanges an authorization code for tokens
func (s *Server) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request, client db.OauthClient) {
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")

	if code == "" {
		s.tokenError(w, "invalid_request", "Authorization code is required")
		return
	}

	// Look up the authorization code
	authCode, err := s.datastore.Q.GetAuthorizationCode(r.Context(), code)
	if err != nil {
		s.tokenError(w, "invalid_grant", "Invalid authorization code")
		return
	}

	// Validate the code hasn't been consumed
	if authCode.ConsumedAt.Valid {
		s.tokenError(w, "invalid_grant", "Authorization code has already been used")
		return
	}

	// Validate the code hasn't expired
	if authCode.ExpiresAt.Before(time.Now()) {
		s.tokenError(w, "invalid_grant", "Authorization code has expired")
		return
	}

	// Validate the client ID matches
	if authCode.ClientID != client.ID {
		s.tokenError(w, "invalid_grant", "Authorization code was not issued to this client")
		return
	}

	// Validate the redirect URI matches
	if authCode.RedirectUri != redirectURI {
		s.tokenError(w, "invalid_grant", "Redirect URI does not match")
		return
	}

	// Verify PKCE code_verifier
	if authCode.CodeChallenge.Valid {
		if codeVerifier == "" {
			s.tokenError(w, "invalid_request", "Code verifier is required")
			return
		}
		// Compute SHA256 hash of the verifier
		hash := sha256.Sum256([]byte(codeVerifier))
		computedChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

		if computedChallenge != authCode.CodeChallenge.String {
			s.tokenError(w, "invalid_grant", "Invalid code verifier")
			return
		}
	}

	// Mark the authorization code as consumed
	err = s.datastore.Q.ConsumeAuthorizationCode(r.Context(), code)
	if err != nil {
		s.tokenError(w, "server_error", "Failed to consume authorization code")
		return
	}

	// Generate tokens
	s.issueTokens(w, r, client, authCode.UserID, authCode.Scope)
}

// handleRefreshTokenGrant exchanges a refresh token for new tokens
func (s *Server) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, client db.OauthClient) {
	refreshToken := r.FormValue("refresh_token")

	if refreshToken == "" {
		s.tokenError(w, "invalid_request", "Refresh token is required")
		return
	}

	// Look up the token by refresh token
	token, err := s.datastore.Q.GetTokenByRefreshToken(r.Context(), sql.NullString{String: refreshToken, Valid: true})
	if err != nil {
		s.tokenError(w, "invalid_grant", "Invalid refresh token")
		return
	}

	// Validate the client ID matches
	if token.ClientID != client.ID {
		s.tokenError(w, "invalid_grant", "Refresh token was not issued to this client")
		return
	}

	// Check if refresh token has expired
	if token.RefreshExpiresAt.Valid && token.RefreshExpiresAt.Time.Before(time.Now()) {
		s.tokenError(w, "invalid_grant", "Refresh token has expired")
		return
	}

	// Revoke the old token
	err = s.datastore.Q.RevokeTokenByRefreshToken(r.Context(), sql.NullString{String: refreshToken, Valid: true})
	if err != nil {
		s.tokenError(w, "server_error", "Failed to revoke old token")
		return
	}

	// Issue new tokens with the same user and scope
	var userID uuid.UUID
	if token.UserID.Valid {
		userID = token.UserID.UUID
	}
	s.issueTokens(w, r, client, userID, token.Scope)
}

// issueTokens generates and stores new access and refresh tokens, then writes the JSON response
func (s *Server) issueTokens(w http.ResponseWriter, r *http.Request, client db.OauthClient, userID uuid.UUID, scope []string) {
	accessToken, err := generateRandomString(32)
	if err != nil {
		s.tokenError(w, "server_error", "Failed to generate access token")
		return
	}

	refreshToken, err := generateRandomString(32)
	if err != nil {
		s.tokenError(w, "server_error", "Failed to generate refresh token")
		return
	}

	// Access token expires in 1 hour, refresh token in 30 days
	accessExpiresAt := time.Now().Add(1 * time.Hour)
	refreshExpiresAt := time.Now().Add(30 * 24 * time.Hour)

	_, err = s.datastore.Q.InsertToken(r.Context(), db.InsertTokenParams{
		AccessToken:      sql.NullString{String: accessToken, Valid: true},
		RefreshToken:     sql.NullString{String: refreshToken, Valid: true},
		UserID:           uuid.NullUUID{UUID: userID, Valid: userID != uuid.Nil},
		ClientID:         client.ID,
		Scope:            scope,
		Column6:          "Bearer",
		ExpiresAt:        accessExpiresAt,
		RefreshExpiresAt: sql.NullTime{Time: refreshExpiresAt, Valid: true},
	})
	if err != nil {
		s.tokenError(w, "server_error", "Failed to store token")
		return
	}

	// Build response
	response := map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    3600, // 1 hour in seconds
		"refresh_token": refreshToken,
		"scope":         strings.Join(scope, " "),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(response)
}

// tokenError writes an OAuth2 error response
func (s *Server) tokenError(w http.ResponseWriter, errorCode, description string) {
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
func (s *Server) handleOauthUserInfo(w http.ResponseWriter, r *http.Request) {
	// temporary no-op
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
func (s *Server) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	// temporary no-op
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
func (s *Server) handleOauthRevoke(w http.ResponseWriter, r *http.Request) {
	// temporary no-op
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
