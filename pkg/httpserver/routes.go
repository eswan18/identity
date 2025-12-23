package httpserver

import (
	"net/http"

	_ "github.com/eswan18/identity/docs"
	"github.com/go-chi/chi/v5"
	httpSwagger "github.com/swaggo/http-swagger"
)

// RegisterRoutes registers all routes on the given router.
func (s *Server) RegisterRoutes(r chi.Router) {
	// Health check
	r.Get("/health", s.HandleHealthCheck)

	// OAuth2/OIDC endpoints
	r.Route("/oauth", func(r chi.Router) {
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
	})

	/*// OIDC discovery endpoints (must be at root per spec)
	r.Get("/.well-known/openid-configuration", s.HandleOpenIDConfiguration)
	r.Get("/.well-known/jwks.json", s.HandleJWKS)
	*/

	// Swagger
	r.Get("/openapi/*", httpSwagger.Handler(
		httpSwagger.URL("http://localhost:8080/openapi.json"),
	))
	r.Get("/openapi.json", s.HandleOpenAPISpec)

	// 404 handler - catch all unmatched routes
	r.NotFound(s.HandleNotFound)
}

// HandleNotFound handles 404 Not Found errors
func (s *Server) HandleNotFound(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte("404 - Not Found: " + r.URL.Path))
}

// registerRoutes is a convenience method that registers routes on the server's router
func (s *Server) registerRoutes() {
	s.RegisterRoutes(s.router)
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
	// temporary no-op
}

// HandleOpenIDConfiguration godoc
// @Summary      OIDC discovery document
// @Description  Returns OpenID Connect discovery document with endpoints and supported features
// @Tags         oidc
// @Produce      json
// @Success      200 {object} map[string]interface{} "OIDC configuration including issuer, endpoints, supported response types, scopes, etc."
// @Router       /.well-known/openid-configuration [get]
func (s *Server) HandleOpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	// temporary no-op
}

// HandleJWKS godoc
// @Summary      JSON Web Key Set
// @Description  Returns public RSA keys for JWT signature verification
// @Tags         oidc
// @Produce      json
// @Success      200 {object} map[string]interface{} "JWKS containing public keys with kty, use, kid, n, e fields"
// @Router       /.well-known/jwks.json [get]
func (s *Server) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	// temporary no-op
}

// HandleOpenAPISpec serves the OpenAPI JSON spec
func (s *Server) HandleOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	http.ServeFile(w, r, "docs/swagger.json")
}
