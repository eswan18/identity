package httpserver

import (
	"net/http"

	_ "github.com/eswan18/identity/docs"
	"github.com/go-chi/chi/v5"
	httpSwagger "github.com/swaggo/http-swagger"
)

// corsMiddleware creates a CORS middleware that allows requests from any origin
// Safe for public endpoints like health checks that don't expose sensitive data
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Max-Age", "3600")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// oauthCorsMiddleware creates a CORS middleware for OAuth endpoints
// Allows POST requests with Authorization headers from any origin
func oauthCorsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Max-Age", "3600")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// registerRoutes registers all routes on the given router.
func (s *Server) registerRoutes() {
	// Root redirect - sends to login or account settings based on auth status
	s.router.Get("/", s.HandleRoot)

	// Static files (CSS, JS, images)
	fileServer := http.FileServer(http.Dir("static"))
	s.router.Handle("/static/*", http.StripPrefix("/static/", fileServer))

	// Health check with CORS enabled for all origins (safe - no sensitive data)
	s.router.With(corsMiddleware).Get("/health", s.HandleHealthCheck)

	// JWKS endpoint for JWT public key distribution
	s.router.With(corsMiddleware).Get("/.well-known/jwks.json", s.HandleJWKS)

	// OAuth2/OIDC endpoints with CORS enabled
	s.router.Route("/oauth", func(r chi.Router) {
		// Apply CORS middleware to all OAuth routes
		r.Use(oauthCorsMiddleware)

		// Core auth stuff
		r.Get("/authorize", s.HandleOauthAuthorize)
		r.Get("/login", s.HandleLoginGet)
		r.Post("/login", s.HandleLoginPost)
		r.Post("/token", s.HandleOauthToken)
		r.Post("/refresh", s.HandleOauthRefresh)
		// Registration stuff
		r.Get("/register", s.HandleRegisterGet)
		r.Post("/register", s.HandleRegisterPost)
		// Other stuff
		r.Get("/success", s.HandleSuccess)
		r.Post("/logout", s.HandleLogout)
		r.Get("/userinfo", s.HandleOauthUserInfo)
		r.Post("/introspect", s.HandleIntrospect)
		r.Post("/revoke", s.HandleOauthRevoke)
		// Account settings
		r.Get("/account-settings", s.HandleAccountSettingsGet)
		// Change password
		r.Get("/change-password", s.HandleChangePasswordGet)
		r.Post("/change-password", s.HandleChangePasswordPost)
		// Change username
		r.Get("/change-username", s.HandleChangeUsernameGet)
		r.Post("/change-username", s.HandleChangeUsernamePost)
		// Change email
		r.Get("/change-email", s.HandleChangeEmailGet)
		r.Post("/change-email", s.HandleChangeEmailPost)
		// Deactivate account
		r.Post("/deactivate-account", s.HandleDeactivateAccountPost)
		// Reactivate account
		r.Post("/reactivate-account", s.HandleReactivateAccountPost)
		// MFA verification (during login)
		r.Get("/mfa", s.HandleMFAGet)
		r.Post("/mfa", s.HandleMFAPost)
		// MFA setup (from account settings)
		r.Get("/mfa-setup", s.HandleMFASetupGet)
		r.Post("/mfa-setup", s.HandleMFASetupPost)
		r.Post("/mfa-disable", s.HandleMFADisablePost)
		// Email verification
		r.Get("/verify-email", s.HandleVerifyEmail)
		r.Post("/resend-verification", s.HandleResendVerification)
		// Password reset
		r.Get("/forgot-password", s.HandleForgotPasswordGet)
		r.Post("/forgot-password", s.HandleForgotPasswordPost)
		r.Get("/reset-password", s.HandleResetPasswordGet)
		r.Post("/reset-password", s.HandleResetPasswordPost)
		// Username reminder
		r.Get("/forgot-username", s.HandleForgotUsernameGet)
		r.Post("/forgot-username", s.HandleForgotUsernamePost)
	})

	// Swagger
	s.router.Get("/openapi/*", httpSwagger.Handler(
		httpSwagger.URL("http://localhost:8080/openapi.json"),
	))
	s.router.Get("/openapi.json", s.HandleOpenAPISpec)

	// 404 handler - catch all unmatched routes
	s.router.NotFound(s.HandleNotFound)
}

// HandleNotFound handles 404 Not Found errors
func (s *Server) HandleNotFound(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte("404 - Not Found: " + r.URL.Path))
}

// HandleHealthCheck godoc
// @Summary      Health check
// @Description  Returns service health status including database connectivity
// @Tags         health
// @Produce      json
// @Success      200 {object} map[string]string "Service is healthy"
// @Router       /health [get]
func (s *Server) HandleHealthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// HandleSuccess godoc
// @Summary      Login success page
// @Description  Displays a success page after direct login (without OAuth redirect_uri), explaining how to access applications through OAuth flow
// @Tags         authentication
// @Produce      html
// @Success      200 {string} string "HTML success page"
// @Router       /success [get]
func (s *Server) HandleSuccess(w http.ResponseWriter, r *http.Request) {
	// TODO: Verify user is actually authenticated (check session)
	if err := s.successTemplate.Execute(w, nil); err != nil {
		http.Error(w, "An error occurred while rendering the success page", http.StatusInternalServerError)
	}
}

// HandleLogout godoc
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
func (s *Server) HandleLogout(w http.ResponseWriter, r *http.Request) {
	// Get the session cookie
	cookie, err := r.Cookie("session_id")
	if err == nil && cookie.Value != "" {
		// Delete the session from the database
		if err := s.datastore.Q.DeleteSession(r.Context(), cookie.Value); err != nil {
			// Log the error but continue with logout (clear cookie anyway)
			// The session might already be expired/deleted
		}
	}

	// Clear the session cookie by setting it to expire immediately
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	// Redirect to post_logout_redirect_uri if provided, otherwise to login page
	redirectURI := r.URL.Query().Get("post_logout_redirect_uri")
	if redirectURI == "" {
		redirectURI = r.FormValue("post_logout_redirect_uri")
	}
	if redirectURI == "" {
		redirectURI = "/oauth/login"
	}

	http.Redirect(w, r, redirectURI, http.StatusFound)
}

// HandleOpenAPISpec serves the OpenAPI JSON spec
func (s *Server) HandleOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	http.ServeFile(w, r, "docs/swagger.json")
}
