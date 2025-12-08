package httpserver

import (
	"fmt"
	"net/http"
	"net/url"

	_ "github.com/eswan18/fcast-auth/docs"
	"github.com/go-chi/chi/v5"
	httpSwagger "github.com/swaggo/http-swagger"
)

func (s *Server) registerRoutes() {
	r := s.router

	// Health check
	r.Get("/health", s.handleHealthCheck)

	// Authentication endpoints
	r.Get("/login", s.handleLoginGet)
	r.Post("/login", s.handleLoginPost)
	r.Post("/logout", s.handleLogout)

	// OAuth2/OIDC endpoints
	r.Route("/oauth", func(r chi.Router) {
		r.Get("/authorize", s.handleAuthorize)
		r.Post("/token", s.handleToken)
		r.Get("/userinfo", s.handleUserInfo)
		r.Post("/introspect", s.handleIntrospect)
		r.Post("/revoke", s.handleRevoke)
	})

	/*// OIDC discovery endpoints (must be at root per spec)
	r.Get("/.well-known/openid-configuration", s.handleOpenIDConfiguration)
	r.Get("/.well-known/jwks.json", s.handleJWKS)
	*/

	// Swagger
	r.Get("/openapi/*", httpSwagger.Handler(
		httpSwagger.URL("http://localhost:8080/openapi.json"),
	))
	r.Get("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		http.ServeFile(w, r, "docs/swagger.json")
	})
}

// handleHealthCheck godoc
// @Summary      Health check
// @Description  Returns service health status including database connectivity
// @Tags         health
// @Produce      json
// @Success      200 {object} map[string]string "Service is healthy"
// @Router       /health [get]
func (s *Server) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

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
	// For now, don't validate client_id
	clientID := r.URL.Query().Get("client_id")
	// TODO: Validate redirect_uri and state
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	scope := r.URL.Query().Get("scope")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")
	if codeChallengeMethod != "S256" {
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

	s.loginTemplate.Execute(w, LoginPageData{
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
	if redirectURI == "" {
		s.renderLoginError(w, http.StatusBadRequest, "Redirect URI is required", oauthParams)
		return
	}
	// Fake validation for now
	if username != "admin" || password != "password" {
		s.renderLoginError(w, http.StatusUnauthorized, "Invalid username or password", oauthParams)
		return
	}

	// TODO: Validate username and password against database
	// TODO: Create authenticated session
	// TODO: Generate authorization code
	// TODO: Redirect to redirect_uri with authorization code
	http.Redirect(w, r, redirectURI, http.StatusFound)
}

// handleLogout godoc
// @Summary      Logout user
// @Description  Invalidates user session and refresh tokens, then redirects to logout URI or default page
// @Tags         authentication
// @Accept       application/x-www-form-urlencoded
// @Produce      html
// @Param        post_logout_redirect_uri query string false "Where to redirect after logout"
// @Param        state                    query string false "State to include in redirect"
// @Success      302 {string} string "Redirect to logout URI or default page"
// @Failure      400 {string} string "Invalid request"
// @Router       /logout [post]
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// temporary no-op
}

// handleAuthorize godoc
// @Summary      OAuth2 authorization endpoint
// @Description  Validates OAuth2 parameters, checks if user is authenticated (via session cookie), renders login page if not authenticated, or generates authorization code and redirects to redirect_uri if authenticated
// @Tags         oauth2
// @Produce      html
// @Param        response_type        query     string  true  "Must be 'code'"
// @Param        client_id            query     string  true  "Registered client identifier"
// @Param        redirect_uri        query     string  true  "Where to send the user after auth"
// @Param        scope               query     string  true  "Requested scopes (e.g., 'openid profile email')"
// @Param        state               query     string  true  "CSRF protection token"
// @Param        code_challenge      query     string  true  "PKCE code challenge (SHA256 hash)"
// @Param        code_challenge_method query   string  true  "Must be 'S256'"
// @Success      302 {string} string "Redirect to redirect_uri with authorization code and state"
// @Failure      302 {string} string "Redirect to redirect_uri with error parameters"
// @Router       /oauth/authorize [get]
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	// temporary no-op
}

// handleToken godoc
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
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	// temporary no-op
}

// handleOpenIDConfiguration godoc
// @Summary      OIDC discovery document
// @Description  Returns OpenID Connect discovery document with endpoints and supported features
// @Tags         oidc
// @Produce      json
// @Success      200 {object} map[string]interface{} "OIDC configuration including issuer, endpoints, supported response types, scopes, etc."
// @Router       /.well-known/openid-configuration [get]
func (s *Server) handleOpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	// temporary no-op
}

// handleJWKS godoc
// @Summary      JSON Web Key Set
// @Description  Returns public RSA keys for JWT signature verification
// @Tags         oidc
// @Produce      json
// @Success      200 {object} map[string]interface{} "JWKS containing public keys with kty, use, kid, n, e fields"
// @Router       /.well-known/jwks.json [get]
func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	// temporary no-op
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
func (s *Server) handleUserInfo(w http.ResponseWriter, r *http.Request) {
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
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	// temporary no-op
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
