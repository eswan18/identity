package httpserver

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
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
func (s *Server) HandleLoginGet(w http.ResponseWriter, r *http.Request) {
	// Extract OAuth parameters (all optional - /login can be accessed standalone or via OAuth flow)
	// Note: /oauth/authorize should validate required OAuth params before redirecting here
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	scope := strings.Split(r.URL.Query().Get("scope"), " ")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")

	// If code_challenge_method is provided, it must be S256 -- meaning a sha256 hash of the code verifier.
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

	// Check for various messages to show
	errorMsg := ""
	if r.URL.Query().Get("registered") == "true" {
		errorMsg = "Account created successfully! Please sign in."
	} else if r.URL.Query().Get("deactivated") == "true" {
		errorMsg = "Your account has been deactivated."
	} else if r.URL.Query().Get("error") == "account_deactivated" {
		errorMsg = "Your account is deactivated. You cannot log in to applications."
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
func (s *Server) HandleLoginPost(w http.ResponseWriter, r *http.Request) {
	log.Printf("[DEBUG] HandleLoginPost: Starting login request")
	username := r.FormValue("username")
	password := r.FormValue("password")
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")
	scope := strings.Split(r.FormValue("scope"), " ")
	codeChallenge := r.FormValue("code_challenge")
	codeChallengeMethod := r.FormValue("code_challenge_method")

	log.Printf("[DEBUG] HandleLoginPost: username=%s, clientID=%s, redirectURI=%s", username, clientID, redirectURI)

	// Extract OAuth parameters into a struct for reuse.
	oauthParams := LoginPageData{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		State:               state,
		Scope:               scope,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
	}
	// Validate credentials - use the function that includes inactive users
	// so we can handle deactivated users appropriately based on the login type
	log.Printf("[DEBUG] HandleLoginPost: Validating credentials for user: %s", username)
	user, err := s.validateCredentialsIncludingInactive(r.Context(), username, password)
	if err != nil {
		log.Printf("[DEBUG] HandleLoginPost: Credential validation failed: %v", err)
		status := http.StatusInternalServerError
		if errors.Is(err, ErrMissingCredentials) {
			status = http.StatusBadRequest
		} else if errors.Is(err, ErrInvalidCredentials) {
			status = http.StatusUnauthorized
		}
		s.renderLoginError(w, status, err.Error(), oauthParams)
		return
	}
	log.Printf("[DEBUG] HandleLoginPost: Credentials validated successfully for user ID: %v", user.ID)

	// Check if user is deactivated and trying to use OAuth login
	// Deactivated users can only log in directly (no client_id) to access account settings
	if !user.IsActive && clientID != "" {
		log.Printf("[DEBUG] HandleLoginPost: Deactivated user %s attempted OAuth login", username)
		s.renderLoginError(w, http.StatusForbidden, ErrAccountDeactivated.Error(), oauthParams)
		return
	}

	// Check if MFA is enabled for this user
	if user.MfaEnabled {
		log.Printf("[DEBUG] HandleLoginPost: MFA enabled for user %s, creating pending session", username)
		pendingID, err := s.createMFAPendingSession(r, user.ID, oauthParams)
		if err != nil {
			log.Printf("[ERROR] HandleLoginPost: Failed to create MFA pending session: %v", err)
			s.renderLoginError(w, http.StatusInternalServerError, "An error occurred", oauthParams)
			return
		}
		// Redirect to MFA verification page
		http.Redirect(w, r, "/oauth/mfa?pending="+pendingID, http.StatusFound)
		return
	}

	// Create authenticated session
	log.Printf("[DEBUG] HandleLoginPost: Creating session for user ID: %v", user.ID)
	session, err := s.createSession(r.Context(), user.ID)
	if err != nil {
		log.Printf("[ERROR] HandleLoginPost: Failed to create session: %v", err)
		s.renderLoginError(w, http.StatusInternalServerError, "An error occurred", oauthParams)
		return
	}
	log.Printf("[DEBUG] HandleLoginPost: Session created successfully: %s", session.ID)

	// Set secure session cookie
	// Secure flag should be true in production (HTTPS), false for local dev
	isSecure := strings.HasPrefix(s.config.HTTPAddress, "https://") || strings.Contains(s.config.HTTPAddress, ":443")
	log.Printf("[DEBUG] HandleLoginPost: Setting session cookie (secure=%v)", isSecure)
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    session.ID,
		Path:     "/",
		Expires:  session.ExpiresAt,
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteLaxMode,
	})

	// Check if this is a direct login (no OAuth flow)
	if clientID == "" {
		// Direct login: redirect to account settings
		log.Printf("[DEBUG] HandleLoginPost: Direct login (no client_id), redirecting to account settings")
		http.Redirect(w, r, "/oauth/account-settings", http.StatusFound)
		return
	}

	// Validate OAuth client, redirect URI, and scopes
	log.Printf("[DEBUG] HandleLoginPost: Validating OAuth client: %s", clientID)
	client, err := s.validateOAuthClient(r.Context(), clientID, redirectURI, scope)
	if err != nil {
		log.Printf("[ERROR] HandleLoginPost: OAuth client validation failed: %v", err)
		s.renderLoginError(w, http.StatusBadRequest, err.Error(), oauthParams)
		return
	}
	log.Printf("[DEBUG] HandleLoginPost: OAuth client validated: %s", client.ID)

	if redirectURI == "" {
		// OAuth flow but no redirect URI - show success page
		log.Printf("[DEBUG] HandleLoginPost: No redirect URI, redirecting to success page")
		http.Redirect(w, r, "/oauth/success", http.StatusFound)
		return
	}

	// Generate and store authorization code
	log.Printf("[DEBUG] HandleLoginPost: Generating authorization code")
	authorizationCode, err := s.generateAuthorizationCode(r.Context(), user.ID, client.ID, redirectURI, scope, codeChallenge, codeChallengeMethod)
	if err != nil {
		log.Printf("[ERROR] HandleLoginPost: Failed to generate authorization code: %v", err)
		s.renderLoginError(w, http.StatusInternalServerError, "An error occurred", oauthParams)
		return
	}
	log.Printf("[DEBUG] HandleLoginPost: Authorization code generated successfully")

	// Build the final redirect URL with the authorization code and other OAuth parameters.
	log.Printf("[DEBUG] HandleLoginPost: Building redirect URL to: %s", redirectURI)
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		log.Printf("[ERROR] HandleLoginPost: Failed to parse redirect URI: %v", err)
		s.renderLoginError(w, http.StatusBadRequest, "Invalid redirect URI", oauthParams)
		return
	}
	q := redirectURL.Query()
	q.Set("state", state)
	q.Set("code", authorizationCode)
	redirectURL.RawQuery = q.Encode()

	log.Printf("[DEBUG] HandleLoginPost: Redirecting to: %s", redirectURL.String())
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
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
