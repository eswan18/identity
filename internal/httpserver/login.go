package httpserver

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/eswan18/identity/internal/auth"
	"github.com/eswan18/identity/internal/db"
	"github.com/google/uuid"
)

const authorizationCodeExpiresIn = 10 * time.Minute

// handleLoginGet godoc
// @Summary      Show login page
// @Description  Displays the login form with OAuth parameters preserved in hidden fields
// @Tags         authentication
// @Produce      html
// @Param        client_id           query     string  true  "Registered client identifier"
// @Param        redirect_uri        query     string  true  "Where to send the user after auth"
// @Param        state               query     string  true  "CSRF protection token"
// @Param        scope               query     string  true  "Requested scopes (e.g., 'openid profile email')"
// @Param        code_challenge      query     string  true  "PKCE code challenge (SHA256 hash)"
// @Param        code_challenge_method query   string  true  "PKCE challenge method (must be 'S256')"
// @Success      200 {string} string "HTML login page"
// @Router       /login [get]
func (s *Server) handleLoginGet(w http.ResponseWriter, r *http.Request) {
	// Extract OAuth parameters (all optional - /login can be accessed standalone or via OAuth flow)
	// Note: /oauth/authorize should validate required OAuth params before redirecting here
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	scope := strings.Split(r.URL.Query().Get("scope"), " ")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")

	// If code_challenge_method is provided, it must be S256
	if codeChallengeMethod != "" && codeChallengeMethod != "S256" {
		if redirectURI != "" {
			// OAuth error: redirect back to client with error parameters
			errorDesc := "Only S256 code challenge method is supported"
			redirectURL := fmt.Sprintf("%s?error=invalid_request&error_description=%s&state=%s",
				redirectURI,
				url.QueryEscape(errorDesc),
				url.QueryEscape(state))
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}
		// No redirect_uri: show error page
		s.renderLoginError(w, http.StatusBadRequest, "Only S256 code challenge method is supported", LoginPageData{
			ClientID:            clientID,
			RedirectURI:         redirectURI,
			State:               state,
			Scope:               scope,
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
		})
		return
	}

	// Check if user just registered (show success message)
	registered := r.URL.Query().Get("registered") == "true"
	errorMsg := ""
	if registered {
		errorMsg = "Account created successfully! Please sign in."
	}

	s.loginTemplate.Execute(w, LoginPageData{
		Error:               errorMsg,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		State:               state,
		Scope:               scope,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
	})
}

// handleLoginPost godoc
// @Summary      Process login
// @Description  Validates username/password, creates authenticated session, generates authorization code, and redirects to client
// @Tags         authentication
// @Accept       application/x-www-form-urlencoded
// @Produce      html
// @Param        username            formData  string  true  "User username"
// @Param        password            formData  string  true  "User password"
// @Param        client_id           formData  string  true  "OAuth client ID"
// @Param        redirect_uri        formData  string  true  "OAuth redirect URI"
// @Param        state               formData  string  true  "CSRF protection token"
// @Param        scope               formData  string  true  "Requested scopes"
// @Param        code_challenge      formData  string  true  "PKCE code challenge"
// @Param        code_challenge_method formData string true  "PKCE challenge method"
// @Success      302 {string} string "Redirect to redirect_uri with authorization code"
// @Failure      400 {string} string "Invalid request parameters"
// @Failure      401 {string} string "Invalid credentials"
// @Router       /login [post]
func (s *Server) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")
	scope := strings.Split(r.FormValue("scope"), " ")
	codeChallenge := r.FormValue("code_challenge")
	codeChallengeMethod := r.FormValue("code_challenge_method")

	// Extract OAuth parameters into a struct for reuse.
	oauthParams := LoginPageData{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		State:               state,
		Scope:               scope,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
	}
	// Validate required fields and re-render login page with error if missing
	if username == "" || password == "" {
		s.renderLoginError(w, http.StatusBadRequest, "Username and password are required", oauthParams)
		return
	}

	// Validate username and password against database
	user, err := s.datastore.Q.GetUserByUsername(r.Context(), username)
	if err == sql.ErrNoRows {
		s.renderLoginError(w, http.StatusUnauthorized, "Invalid username or password", oauthParams)
		return
	}
	if err != nil {
		s.renderLoginError(w, http.StatusInternalServerError, "An error occurred", oauthParams)
		return
	}

	valid, err := auth.VerifyPassword(password, user.PasswordHash)
	if err != nil {
		s.renderLoginError(w, http.StatusInternalServerError, "An error occurred", oauthParams)
		return
	}
	if !valid {
		s.renderLoginError(w, http.StatusUnauthorized, "Invalid username or password", oauthParams)
		return
	}

	// Create authenticated session
	sessionID, err := generateSessionID()
	if err != nil {
		s.renderLoginError(w, http.StatusInternalServerError, "An error occurred", oauthParams)
		return
	}

	// Session expires in 24 hours
	expiresAt := time.Now().Add(24 * time.Hour)
	err = s.datastore.Q.CreateSession(r.Context(), db.CreateSessionParams{
		ID:        sessionID,
		UserID:    user.ID,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		s.renderLoginError(w, http.StatusInternalServerError, "An error occurred", oauthParams)
		return
	}

	// Set secure session cookie
	// Secure flag should be true in production (HTTPS), false for local dev
	isSecure := strings.HasPrefix(s.config.HTTPAddress, "https://") || strings.Contains(s.config.HTTPAddress, ":443")
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteLaxMode,
	})
	if redirectURI == "" {
		// Direct login (no OAuth):
		// There's no real reason to log in without a redirect except to check your password, but maybe someday.
		// For now, we'll just show a success page explaining how to access applications.
		http.Redirect(w, r, "/success", http.StatusFound)
		return
	}

	// Validations...
	// Is this a real client?
	client, err := s.datastore.Q.GetOAuthClientByClientID(r.Context(), clientID)
	if err != nil {
		if err == sql.ErrNoRows {
			s.renderLoginError(w, http.StatusBadRequest, "Invalid client ID", oauthParams)
			return
		}
		s.renderLoginError(w, http.StatusInternalServerError, "An error occurred", oauthParams)
		return
	}
	// Is the redirect URI valid for this client?
	if !slices.Contains(client.RedirectUris, redirectURI) {
		s.renderLoginError(w, http.StatusBadRequest, "Invalid redirect URI", oauthParams)
		return
	}
	// Are the requested scopes valid for this client?
	if !containsAll(client.AllowedScopes, scope) {
		s.renderLoginError(w, http.StatusBadRequest, "Invalid scope", oauthParams)
		return
	}

	// Generate and store authorization code
	authorizationCode, err := s.createNewAuthorizationCode(r.Context(), user.ID, client.ID, redirectURI, scope, codeChallenge, codeChallengeMethod)
	if err != nil {
		s.renderLoginError(w, http.StatusInternalServerError, "An error occurred", oauthParams)
		return
	}

	// Build the final redirect URL with the authorization code and other OAuth parameters.
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		s.renderLoginError(w, http.StatusBadRequest, "Invalid redirect URI", oauthParams)
		return
	}
	q := redirectURL.Query()
	q.Set("state", state)
	q.Set("code", authorizationCode)
	redirectURL.RawQuery = q.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

func (s *Server) createNewAuthorizationCode(ctx context.Context, userID uuid.UUID, clientID uuid.UUID, redirectURI string, scope []string, codeChallenge string, codeChallengeMethod string) (string, error) {
	code, err := generateAuthorizationCode()
	if err != nil {
		return "", err
	}
	err = s.datastore.Q.InsertAuthorizationCode(ctx, db.InsertAuthorizationCodeParams{
		Code:                code,
		UserID:              userID,
		ClientID:            clientID,
		RedirectUri:         redirectURI,
		Scope:               scope,
		CodeChallenge:       sql.NullString{String: codeChallenge, Valid: codeChallenge != ""},
		CodeChallengeMethod: sql.NullString{String: codeChallengeMethod, Valid: codeChallengeMethod != ""},
		ExpiresAt:           time.Now().Add(authorizationCodeExpiresIn),
	})
	if err != nil {
		return "", err
	}
	return code, nil
}

// renderLoginError renders the login page with an error message, preserving OAuth parameters.
// It handles template execution errors gracefully by falling back to the error template.
func (s *Server) renderLoginError(w http.ResponseWriter, statusCode int, errorMsg string, oauthParams LoginPageData) {
	w.WriteHeader(statusCode)
	err := s.loginTemplate.Execute(w, LoginPageData{
		Error:               errorMsg,
		ClientID:            oauthParams.ClientID,
		RedirectURI:         oauthParams.RedirectURI,
		State:               oauthParams.State,
		Scope:               oauthParams.Scope,
		CodeChallenge:       oauthParams.CodeChallenge,
		CodeChallengeMethod: oauthParams.CodeChallengeMethod,
	})
	if err != nil {
		// Fallback to error template if login template fails
		err = s.errorTemplate.Execute(w, ErrorPageData{
			Title:       "Internal Server Error",
			Message:     "An error occurred while rendering the login page",
			Details:     err.Error(),
			ErrorCode:   "500",
			RedirectURI: oauthParams.RedirectURI,
		})
		if err != nil {
			// Last resort: plain text error
			http.Error(w, "An error occurred while rendering the error page", http.StatusInternalServerError)
		}
	}
}

// generateSessionID generates a cryptographically secure random session ID
func generateSessionID() (string, error) {
	bytes := make([]byte, 32) // 256 bits
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// generateAuthorizationCode generates a cryptographically secure random authorization code
func generateAuthorizationCode() (string, error) {
	bytes := make([]byte, 32) // 256 bits
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}
