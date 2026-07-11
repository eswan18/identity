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
	nonce := r.URL.Query().Get("nonce")

	// If code_challenge_method is provided, it must be S256 -- meaning a sha256 hash of the code verifier.
	if codeChallengeMethod != "" && codeChallengeMethod != "S256" {
		oauthParams := LoginPageData{
			ClientID:            clientID,
			RedirectURI:         redirectURI,
			State:               state,
			Scope:               scope,
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
			Nonce:               nonce,
		}

		// Only redirect this OAuth error back to the client if client_id + redirect_uri have
		// been confirmed valid against the registered client. Blindly redirecting to a raw,
		// unvalidated redirect_uri is an open redirect (RFC 6749 4.1.2.1 requires validating
		// client_id/redirect_uri before trusting them for error redirects). This mirrors the
		// validate-before-redirect pattern used in HandleOauthAuthorize / HandleConsentPost.
		if clientID != "" && redirectURI != "" {
			if _, err := s.validateOAuthClientRedirect(r.Context(), clientID, redirectURI); err == nil {
				// OAuth error: redirect back to client with error parameters
				errorDesc := "Only S256 code challenge method is supported"
				redirectURL := fmt.Sprintf("%s?error=invalid_request&error_description=%s&state=%s",
					redirectURI,
					url.QueryEscape(errorDesc),
					url.QueryEscape(state))
				http.Redirect(w, r, redirectURL, http.StatusFound)
				return
			}
		}
		// No redirect_uri, or client_id/redirect_uri failed validation: show error page
		// locally rather than redirecting to an unverified destination.
		s.renderLoginError(w, r, http.StatusBadRequest, "Only S256 code challenge method is supported", oauthParams)
		return
	}

	// Check for various messages to show
	errorMsg := ""
	if r.URL.Query().Get("registered") == "true" {
		errorMsg = "Account created successfully! Please check your email to verify your account."
	} else if r.URL.Query().Get("email_verified") == "true" {
		errorMsg = "Email verified successfully! Please sign in."
	} else if r.URL.Query().Get("password_reset") == "true" {
		errorMsg = "Password reset successfully! Please sign in with your new password."
	} else if r.URL.Query().Get("password_changed") == "true" {
		errorMsg = "Password changed successfully! Please sign in again."
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
		Nonce:               nonce,
		CSRFToken:           s.ensureCSRFToken(w, r),
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
	s.debugf("HandleLoginPost: Starting login request")
	username := r.FormValue("username")
	password := r.FormValue("password")
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")
	scope := strings.Split(r.FormValue("scope"), " ")
	codeChallenge := r.FormValue("code_challenge")
	codeChallengeMethod := r.FormValue("code_challenge_method")
	nonce := r.FormValue("nonce")

	// Extract OAuth parameters into a struct for reuse.
	oauthParams := LoginPageData{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		State:               state,
		Scope:               scope,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Nonce:               nonce,
	}
	// Validate credentials - use the function that includes inactive users
	// so we can handle deactivated users appropriately based on the login type
	user, err := s.validateCredentialsIncludingInactive(r.Context(), username, password)
	if err != nil {
		s.debugf("HandleLoginPost: Credential validation failed: %v", err)
		status := http.StatusInternalServerError
		if errors.Is(err, ErrMissingCredentials) {
			status = http.StatusBadRequest
		} else if errors.Is(err, ErrInvalidCredentials) {
			status = http.StatusUnauthorized
		}
		s.renderLoginError(w, r, status, err.Error(), oauthParams)
		return
	}
	s.debugf("HandleLoginPost: Credentials validated successfully for user ID: %v", user.ID)

	// Check if user is deactivated and trying to use OAuth login
	// Deactivated users can only log in directly (no client_id) to access account settings
	if !user.IsActive && clientID != "" {
		s.debugf("HandleLoginPost: Deactivated user (ID: %v) attempted OAuth login", user.ID)
		s.renderLoginError(w, r, http.StatusForbidden, ErrAccountDeactivated.Error(), oauthParams)
		return
	}

	// Check if MFA is enabled for this user
	if user.MfaEnabled {
		s.debugf("HandleLoginPost: MFA enabled for user (ID: %v), creating pending session", user.ID)
		pendingID, err := s.createMFAPendingSession(r, user.ID, oauthParams)
		if err != nil {
			log.Printf("[ERROR] HandleLoginPost: Failed to create MFA pending session: %v", err)
			s.renderLoginError(w, r, http.StatusInternalServerError, "An error occurred", oauthParams)
			return
		}
		// Redirect to MFA verification page
		http.Redirect(w, r, "/oauth/mfa?pending="+pendingID, http.StatusFound)
		return
	}

	// Create authenticated session
	s.debugf("HandleLoginPost: Creating session for user ID: %v", user.ID)
	session, err := s.createSession(r.Context(), user.ID)
	if err != nil {
		log.Printf("[ERROR] HandleLoginPost: Failed to create session: %v", err)
		s.renderLoginError(w, r, http.StatusInternalServerError, "An error occurred", oauthParams)
		return
	}
	// Log only the user ID, never the session token itself: session.ID is the bearer
	// value sent as the session_id cookie, so writing it to logs would let anyone with
	// log access hijack the session (same class of issue as the reset/verification
	// tokens -- see the request-logging middleware in logging.go).
	s.debugf("HandleLoginPost: Session created successfully for user ID: %v", user.ID)

	// Update last login timestamp
	if err := s.datastore.Q.UpdateUserLastLogin(r.Context(), user.ID); err != nil {
		log.Printf("[ERROR] HandleLoginPost: Failed to update last login time: %v", err)
		// Non-fatal error - continue with login
	}

	// Set the authenticated session cookie.
	s.setSessionCookie(w, session)

	// Redirect onward: back into the OAuth authorize flow (which now finds the user
	// authenticated and handles consent + code issuance), or to account settings for a
	// direct login with no OAuth flow in progress.
	s.redirectAfterAuth(w, r, oauthParams)
}

// renderLoginError renders the login page with an error message, preserving OAuth parameters.
// It handles template execution errors gracefully by falling back to the error template.
func (s *Server) renderLoginError(w http.ResponseWriter, r *http.Request, statusCode int, errorMsg string, oauthParams LoginPageData) {
	// Ensure the CSRF token/cookie before writing the status line, so the re-rendered
	// login form carries a token the eventual POST can echo back.
	csrfToken := s.ensureCSRFToken(w, r)
	w.WriteHeader(statusCode)
	err := s.loginTemplate.Execute(w, LoginPageData{
		Error:               errorMsg,
		ClientID:            oauthParams.ClientID,
		RedirectURI:         oauthParams.RedirectURI,
		State:               oauthParams.State,
		Scope:               oauthParams.Scope,
		CodeChallenge:       oauthParams.CodeChallenge,
		CodeChallengeMethod: oauthParams.CodeChallengeMethod,
		Nonce:               oauthParams.Nonce,
		CSRFToken:           csrfToken,
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

// setSessionCookie writes the authenticated session cookie. The Secure attribute is
// enabled when the service is actually reached over HTTPS (production) and left off
// for plain-HTTP local development; see Server.isSecureContext for how that's decided.
func (s *Server) setSessionCookie(w http.ResponseWriter, session Session) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    session.ID,
		Path:     "/",
		Expires:  session.ExpiresAt,
		HttpOnly: true,
		Secure:   s.isSecureContext(),
		SameSite: http.SameSiteLaxMode,
	})
}

// buildAuthorizeURL builds the /oauth/authorize URL used to (re)enter the OAuth flow
// once the user is authenticated. It mirrors the parameters originally supplied by the
// client; the authorize endpoint re-validates client_id, redirect_uri and scope on
// arrival, so these values are not trusted blindly.
func buildAuthorizeURL(p LoginPageData) string {
	q := url.Values{
		"client_id":             {p.ClientID},
		"redirect_uri":          {p.RedirectURI},
		"response_type":         {"code"},
		"scope":                 {strings.Join(p.Scope, " ")},
		"state":                 {p.State},
		"code_challenge":        {p.CodeChallenge},
		"code_challenge_method": {p.CodeChallengeMethod},
		"nonce":                 {p.Nonce},
	}
	return "/oauth/authorize?" + q.Encode()
}

// redirectAfterAuth sends a freshly-authenticated user onward. When an OAuth client
// initiated the flow (client_id present) the user is routed back through
// /oauth/authorize to handle consent and authorization-code issuance; otherwise this
// was a direct login and the user is taken to account settings.
func (s *Server) redirectAfterAuth(w http.ResponseWriter, r *http.Request, p LoginPageData) {
	if p.ClientID == "" {
		http.Redirect(w, r, "/oauth/account-settings", http.StatusFound)
		return
	}
	http.Redirect(w, r, buildAuthorizeURL(p), http.StatusFound)
}
