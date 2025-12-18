package httpserver

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/eswan18/identity/internal/auth"
	"github.com/eswan18/identity/internal/db"
)

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
	scope := r.URL.Query().Get("scope")
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
	scope := r.FormValue("scope")
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
	user, err := s.datastore.Q.GetUserByUsername(context.Background(), username)
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
	err = s.datastore.Q.CreateSession(context.Background(), db.CreateSessionParams{
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

	// Handle OAuth flow vs direct login
	if redirectURI != "" {
		// OAuth flow: Generate authorization code and redirect to redirect_uri
		// TODO: Generate authorization code
		// TODO: Redirect to redirect_uri with authorization code
		http.Redirect(w, r, redirectURI, http.StatusFound)
		return
	}

	// Direct login (no OAuth): Show success page explaining how to access applications
	http.Redirect(w, r, "/success", http.StatusFound)
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
