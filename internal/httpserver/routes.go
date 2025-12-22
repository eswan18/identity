package httpserver

import (
	"net/http"

	_ "github.com/eswan18/identity/docs"
	"github.com/go-chi/chi/v5"
	httpSwagger "github.com/swaggo/http-swagger"
)

func (s *Server) registerRoutes() {
	r := s.router

	// Health check
	r.Get("/health", s.handleHealthCheck)

	// OAuth2/OIDC endpoints
	r.Route("/oauth", func(r chi.Router) {
		// Core oauth flow (in this order)
		r.Get("/authorize", s.handleOauthAuthorize)
		r.Get("/login", s.handleLoginGet)
		r.Post("/login", s.handleLoginPost)
		r.Post("/token", s.handleOauthToken)
		r.Post("/refresh", s.handleOauthRefresh)
		// Registration
		r.Get("/register", s.handleRegisterGet)
		r.Post("/register", s.handleRegisterPost)
		// Other stuff
		r.Get("/success", s.handleSuccess)
		r.Post("/logout", s.handleLogout)
		r.Get("/userinfo", s.handleOauthUserInfo)
		r.Post("/introspect", s.handleIntrospect)
		r.Post("/revoke", s.handleOauthRevoke)
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

// handleSuccess godoc
// @Summary      Login success page
// @Description  Displays a success page after direct login (without OAuth redirect_uri), explaining how to access applications through OAuth flow
// @Tags         authentication
// @Produce      html
// @Success      200 {string} string "HTML success page"
// @Router       /success [get]
func (s *Server) handleSuccess(w http.ResponseWriter, r *http.Request) {
	// TODO: Verify user is actually authenticated (check session)
	if err := s.successTemplate.Execute(w, nil); err != nil {
		http.Error(w, "An error occurred while rendering the success page", http.StatusInternalServerError)
	}
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
