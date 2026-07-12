package httpserver

import (
	"net/http"
	"slices"

	_ "github.com/eswan18/identity/docs"
	"github.com/eswan18/identity/pkg/views"
	"github.com/go-chi/chi/v5"
	httpSwagger "github.com/swaggo/http-swagger"
)

// newCorsMiddleware creates a CORS middleware with the given allowed methods and headers.
func newCorsMiddleware(methods, headers string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", methods)
			w.Header().Set("Access-Control-Allow-Headers", headers)
			w.Header().Set("Access-Control-Max-Age", "3600")

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// corsMiddleware allows GET requests with Content-Type headers from any origin.
// Safe for public endpoints like health checks that don't expose sensitive data.
var corsMiddleware = newCorsMiddleware("GET, OPTIONS", "Content-Type")

// oauthCorsMiddleware allows GET/POST requests with Authorization headers from any origin.
var oauthCorsMiddleware = newCorsMiddleware("GET, POST, OPTIONS", "Content-Type, Authorization")

// staticPathPrefix is the URL path prefix under which static assets (CSS,
// JS, images) are served. It's a package-level constant, rather than a
// literal duplicated in two places, so that rateLimitMiddleware (see
// ratelimit.go) can exempt static-asset requests from per-IP rate limiting
// using the exact same prefix the static file server is mounted on below -
// keeping the mount point and the exemption from silently drifting apart.
const staticPathPrefix = "/static/"

// registerRoutes registers all routes on the given router.
func (s *Server) registerRoutes() {
	// Root redirect - sends to login or account settings based on auth status
	s.router.Get("/", s.HandleRoot)

	// Static files (CSS, JS, images). Exempt from rateLimitMiddleware (see
	// staticPathPrefix above and the exemption check in ratelimit.go): a
	// single page load pulls the HTML plus several static assets, and the
	// per-IP budget is meant to limit abuse of auth/API endpoints, not
	// ordinary asset fetches.
	fileServer := http.FileServer(http.Dir("static"))
	s.router.Handle(staticPathPrefix+"*", http.StripPrefix(staticPathPrefix, fileServer))

	// Health check with CORS enabled for all origins (safe - no sensitive data)
	s.router.With(corsMiddleware).Get("/health", s.HandleHealthCheck)

	// JWKS endpoint for JWT public key distribution
	s.router.With(corsMiddleware).Get("/.well-known/jwks.json", s.HandleJWKS)

	// OIDC Discovery endpoint
	s.router.With(corsMiddleware).Get("/.well-known/openid-configuration", s.HandleOIDCDiscovery)

	// OAuth2/OIDC endpoints with CORS enabled
	s.router.Route("/oauth", func(r chi.Router) {
		// Apply CORS middleware to all OAuth routes
		r.Use(oauthCorsMiddleware)

		// --- Machine-to-machine / non-browser endpoints (NO CSRF) ---
		// These authenticate with Authorization headers, client credentials, or
		// single-use tokens in the request body and have no browser form or
		// session_id cookie. Requiring a CSRF token here would break every
		// programmatic OAuth2/OIDC client, so they are deliberately kept out of the
		// CSRF-protected group below.
		r.Get("/authorize", s.HandleOauthAuthorize)
		r.Post("/token", s.HandleOauthToken)
		r.Post("/introspect", s.HandleIntrospect)
		r.Post("/revoke", s.HandleOauthRevoke)
		// OIDC Core §5.3 requires the UserInfo endpoint to accept both GET and
		// POST. Both share HandleOauthUserInfo (the header/form token
		// resolution lives in the handler); POST stays in this
		// machine-endpoints section, NOT the CSRF group below, because it is
		// Bearer-authenticated (or, for POST, a form-encoded access_token per
		// RFC 6750 §2.2) rather than session-cookie authenticated - putting it
		// in the CSRF group would wrongly demand a csrf_token from API clients.
		r.Get("/userinfo", s.HandleOauthUserInfo)
		r.Post("/userinfo", s.HandleOauthUserInfo)
		r.Get("/success", s.HandleSuccess)
		// Email verification link (GET, single-use token in the query string).
		r.Get("/verify-email", s.HandleVerifyEmail)
		// Logout via GET is the OIDC RP-Initiated Logout redirect target: browsers
		// navigate to end_session_endpoint, so there is no form to carry a token and
		// GET is a safe method anyway. The POST form variant lives in the CSRF group.
		r.Get("/logout", s.HandleLogout)

		// Change avatar upload (POST only). Registered here, ahead of the CSRF
		// group below, with its own explicit middleware chain - maxAvatarUploadBytes,
		// THEN csrfMiddleware, THEN requireActiveUser - specifically so the
		// request-body size cap in maxAvatarUploadBytes takes effect before
		// csrfMiddleware's r.FormValue call, which would otherwise trigger an
		// unbounded multipart parse of this route's multipart/form-data body
		// first. See maxAvatarUploadBytes in middleware.go for the full
		// explanation. The GET variant has no body to bound, so it stays in the
		// CSRF group below like every other account route.
		r.With(s.maxAvatarUploadBytes, s.csrfMiddleware, s.requireActiveUser).
			Post("/change-avatar", s.HandleChangeAvatarPost)

		// --- Browser, session-cookie form endpoints (CSRF protected) ---
		// Every state-changing POST here is driven by a server-rendered HTML form
		// authenticated by the session_id cookie, so it is vulnerable to CSRF and is
		// guarded by the double-submit-cookie check in csrfMiddleware. Safe GET
		// handlers are included so the group is cohesive; csrfMiddleware never checks
		// GET/HEAD/OPTIONS and each GET seeds the csrf_token cookie via ensureCSRFToken.
		r.Group(func(r chi.Router) {
			r.Use(s.csrfMiddleware)

			// Core auth
			r.Get("/login", s.HandleLoginGet)
			r.Post("/login", s.HandleLoginPost)
			r.Get("/consent", s.HandleConsentGet)
			r.Post("/consent", s.HandleConsentPost)
			// Registration
			r.Get("/register", s.HandleRegisterGet)
			r.Post("/register", s.HandleRegisterPost)
			// Logout (POST form variant)
			r.Post("/logout", s.HandleLogout)
			// MFA verification (during login). This is the login-time challenge
			// that runs BEFORE the user is fully authenticated; it does not use
			// getUserFromSession and so stays out of the requireUser groups below.
			r.Get("/mfa", s.HandleMFAGet)
			r.Post("/mfa", s.HandleMFAPost)
			// Password reset
			r.Get("/forgot-password", s.HandleForgotPasswordGet)
			r.Post("/forgot-password", s.HandleForgotPasswordPost)
			r.Get("/reset-password", s.HandleResetPasswordGet)
			r.Post("/reset-password", s.HandleResetPasswordPost)
			// Username reminder
			r.Get("/forgot-username", s.HandleForgotUsernameGet)
			r.Post("/forgot-username", s.HandleForgotUsernamePost)

			// --- Authenticated account routes ---
			// These handlers all resolve the current user from the session
			// cookie. The requireUser middlewares perform that lookup once (and
			// redirect to /oauth/login on failure), so the handlers pull the user
			// from the request context instead of repeating the boilerplate.

			// requireActiveUser: account operations that require an ACTIVE user.
			r.Group(func(r chi.Router) {
				r.Use(s.requireActiveUser)

				// Change password
				r.Get("/change-password", s.HandleChangePasswordGet)
				r.Post("/change-password", s.HandleChangePasswordPost)
				// Change username
				r.Get("/change-username", s.HandleChangeUsernameGet)
				r.Post("/change-username", s.HandleChangeUsernamePost)
				// Change email
				r.Get("/change-email", s.HandleChangeEmailGet)
				r.Post("/change-email", s.HandleChangeEmailPost)
				// Edit profile
				r.Get("/edit-profile", s.HandleEditProfileGet)
				r.Post("/edit-profile", s.HandleEditProfilePost)
				// Change avatar (GET only here; the POST upload is registered
				// separately above, ahead of this CSRF group - see the comment
				// by that registration for why).
				r.Get("/change-avatar", s.HandleChangeAvatarGet)
				r.Post("/delete-avatar", s.HandleDeleteAvatarPost)
				// MFA setup / disable (post-auth account operations)
				r.Get("/mfa-setup", s.HandleMFASetupGet)
				r.Post("/mfa-setup", s.HandleMFASetupPost)
				r.Post("/mfa-disable", s.HandleMFADisablePost)
				// Email verification (resend from account settings)
				r.Post("/resend-verification", s.HandleResendVerification)
			})

			// requireUser: account operations that must remain reachable for a
			// DEACTIVATED user (these previously used
			// getUserFromSessionIncludingInactive).
			r.Group(func(r chi.Router) {
				r.Use(s.requireUser)

				// Account settings
				r.Get("/account-settings", s.HandleAccountSettingsGet)
				// Deactivate account
				r.Post("/deactivate-account", s.HandleDeactivateAccountPost)
				// Reactivate account
				r.Post("/reactivate-account", s.HandleReactivateAccountPost)
			})
		})
	})

	// Admin API endpoints (require Bearer token with admin scopes)
	s.router.Route("/admin", func(r chi.Router) {
		// Apply CORS middleware for API access
		r.Use(oauthCorsMiddleware)

		// User management
		r.With(s.AdminAuthMiddleware("admin:users:write")).Post("/users", s.HandleAdminCreateUser)
		r.With(s.AdminAuthMiddleware("admin:users:read")).Get("/users", s.HandleAdminListUsers)
		r.With(s.AdminAuthMiddleware("admin:users:read")).Get("/users/{id}", s.HandleAdminGetUser)
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
	_, err := s.getSessionFromCookie(r)
	if err != nil {
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}
	// The success page contains a POST logout form (a CSRF-protected route), so it
	// must carry a CSRF token even though the success GET itself is not checked.
	if err := views.Success(views.SuccessView{CSRFToken: s.ensureCSRFToken(w, r)}).Render(r.Context(), w); err != nil {
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
		Secure:   s.isSecureContext(),
		SameSite: http.SameSiteLaxMode,
	})

	// Redirect to post_logout_redirect_uri if provided and valid, otherwise to login page.
	// Per OIDC RP-Initiated Logout, the URI must be validated against the client's
	// registered redirect URIs. A client_id parameter is required to identify the client.
	redirectURI := "/oauth/login"
	postLogoutURI := r.URL.Query().Get("post_logout_redirect_uri")
	if postLogoutURI == "" {
		postLogoutURI = r.FormValue("post_logout_redirect_uri")
	}
	if postLogoutURI != "" {
		clientID := r.URL.Query().Get("client_id")
		if clientID != "" {
			client, err := s.datastore.Q.GetOAuthClientByClientID(r.Context(), clientID)
			if err == nil && slices.Contains(client.RedirectUris, postLogoutURI) {
				redirectURI = postLogoutURI
			}
		}
	}

	http.Redirect(w, r, redirectURI, http.StatusFound)
}

// HandleOpenAPISpec serves the OpenAPI JSON spec
func (s *Server) HandleOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	http.ServeFile(w, r, "docs/swagger.json")
}
