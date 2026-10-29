package httpserver

import (
	"errors"
	"log"
	"net/http"

	"github.com/eswan18/identity/pkg/views"
)

// handleLoginGet godoc
// @Summary      Show login page
// @Description  Displays the login form, carrying the OAuth authorization request (if any) in a hidden field
// @Tags         authentication
// @Produce      html
// @Param        authorize_query     query     string  false "The original /oauth/authorize query string, when the sign-in is part of an OAuth flow"
// @Success      200 {string} string "HTML login page"
// @Router       /login [get]
func (s *Server) HandleLoginGet(w http.ResponseWriter, r *http.Request) {
	// The authorization request this sign-in belongs to. It is optional: /login
	// can be used directly to reach account settings. /oauth/authorize validates
	// it in full once the user is signed in.
	request := carriedAuthorizeRequest(r)
	p := request.params()

	// If code_challenge_method is provided, it must be S256 -- meaning a sha256 hash of the code verifier.
	if p.CodeChallengeMethod != "" && p.CodeChallengeMethod != "S256" {
		// Only redirect this OAuth error back to the client if client_id + redirect_uri have
		// been confirmed valid against the registered client. Blindly redirecting to a raw,
		// unvalidated redirect_uri is an open redirect (RFC 6749 4.1.2.1 requires validating
		// client_id/redirect_uri before trusting them for error redirects). This mirrors the
		// validate-before-redirect pattern used in HandleOauthAuthorize / HandleConsentPost.
		if p.ClientID != "" && p.RedirectURI != "" {
			if _, err := s.validateOAuthClientRedirect(r.Context(), p.ClientID, p.RedirectURI); err == nil {
				s.respondWithError(w, r, p, "invalid_request", "Only S256 code challenge method is supported")
				return
			}
		}
		// No redirect_uri, or client_id/redirect_uri failed validation: show error page
		// locally rather than redirecting to an unverified destination.
		s.renderLoginError(w, r, http.StatusBadRequest, "Only S256 code challenge method is supported", request)
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
	} else if r.URL.Query().Get("error") == "mfa_throttled" {
		errorMsg = "Too many incorrect verification codes. Please wait a few minutes before trying again. " +
			"If your codes keep being rejected, check that your authenticator device's clock is correct."
	}

	view := views.LoginView{
		Error:          errorMsg,
		AuthorizeQuery: string(request),
		ReturnTo:       carriedReturnTo(r),
		CSRFToken:      s.ensureCSRFToken(w, r),
	}
	if err := views.Login(view).Render(r.Context(), w); err != nil {
		log.Printf("[ERROR] HandleLoginGet: Failed to render login page: %v", err)
	}
}

// handleLoginPost godoc
// @Summary      Process login
// @Description  Validates username/password, creates authenticated session, and resumes the OAuth authorization request the form carried (or goes to account settings)
// @Tags         authentication
// @Accept       application/x-www-form-urlencoded
// @Produce      html
// @Param        username            formData  string  true  "User username"
// @Param        password            formData  string  true  "User password"
// @Param        authorize_query     formData  string  false "The original /oauth/authorize query string, when the sign-in is part of an OAuth flow"
// @Success      302 {string} string "Redirect back to /oauth/authorize, to MFA, or to account settings"
// @Failure      400 {string} string "Invalid request parameters"
// @Failure      401 {string} string "Invalid credentials"
// @Router       /login [post]
func (s *Server) HandleLoginPost(w http.ResponseWriter, r *http.Request) {
	s.debugf("HandleLoginPost: Starting login request")
	username := r.FormValue("username")
	password := r.FormValue("password")
	request := carriedAuthorizeRequest(r)

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
		s.renderLoginError(w, r, status, err.Error(), request)
		return
	}
	s.debugf("HandleLoginPost: Credentials validated successfully for user ID: %v", user.ID)

	// Check if user is deactivated and trying to use OAuth login
	// Deactivated users can only log in directly (no client_id) to access account settings
	if !user.IsActive && request.inFlow() {
		s.debugf("HandleLoginPost: Deactivated user (ID: %v) attempted OAuth login", user.ID)
		s.renderLoginError(w, r, http.StatusForbidden, ErrAccountDeactivated.Error(), request)
		return
	}

	// Check if MFA is enabled for this user
	if user.MfaEnabled {
		s.debugf("HandleLoginPost: MFA enabled for user (ID: %v), creating pending session", user.ID)
		pendingID, err := s.createMFAPendingSession(r, user.ID, request)
		if err != nil {
			log.Printf("[ERROR] HandleLoginPost: Failed to create MFA pending session: %v", err)
			s.renderLoginError(w, r, http.StatusInternalServerError, "An error occurred", request)
			return
		}
		// Redirect to MFA verification page, still carrying the page to return to.
		http.Redirect(w, r, withReturnTo("/oauth/mfa?pending="+pendingID, carriedReturnTo(r)), http.StatusFound)
		return
	}

	// Create authenticated session
	s.debugf("HandleLoginPost: Creating session for user ID: %v", user.ID)
	session, err := s.createSession(r.Context(), user.ID)
	if err != nil {
		log.Printf("[ERROR] HandleLoginPost: Failed to create session: %v", err)
		s.renderLoginError(w, r, http.StatusInternalServerError, "An error occurred", request)
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
	s.redirectAfterAuth(w, r, request)
}

// renderLoginError renders the login page with an error message, keeping the
// authorization request. It handles template execution errors gracefully by
// falling back to the error template.
func (s *Server) renderLoginError(w http.ResponseWriter, r *http.Request, statusCode int, errorMsg string, request authorizeRequest) {
	// Ensure the CSRF token/cookie before writing the status line, so the re-rendered
	// login form carries a token the eventual POST can echo back.
	csrfToken := s.ensureCSRFToken(w, r)
	w.WriteHeader(statusCode)
	err := views.Login(views.LoginView{
		Error:          errorMsg,
		AuthorizeQuery: string(request),
		ReturnTo:       carriedReturnTo(r),
		CSRFToken:      csrfToken,
	}).Render(r.Context(), w)
	if err != nil {
		// Fallback to error template if login template fails
		err = views.Error(views.ErrorView{
			Title:       "Internal Server Error",
			Message:     "An error occurred while rendering the login page",
			Details:     err.Error(),
			ErrorCode:   "500",
			RedirectURI: request.params().RedirectURI,
		}).Render(r.Context(), w)
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

// redirectAfterAuth sends a freshly-authenticated user onward. When an OAuth client
// initiated the flow the user is routed back through /oauth/authorize, with the
// client's original request, to handle consent and authorization-code issuance;
// otherwise this was a direct login and the user is taken to the page they asked
// for before signing in (carriedReturnTo), or to account settings.
func (s *Server) redirectAfterAuth(w http.ResponseWriter, r *http.Request, request authorizeRequest) {
	if !request.inFlow() {
		http.Redirect(w, r, directSignInDestination(r), http.StatusFound)
		return
	}
	http.Redirect(w, r, request.authorizeURL(), http.StatusFound)
}

// directSignInDestination is where a sign-in outside an OAuth flow lands: the
// page the request carried as the one to return to, if it is a safe path, or
// account settings.
func directSignInDestination(r *http.Request) string {
	if returnTo := carriedReturnTo(r); returnTo != "" {
		return returnTo
	}
	return defaultAfterSignIn
}
