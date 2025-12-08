package httpserver

import (
	"net/http"

	_ "github.com/eswan18/fcast-auth/docs"
	"github.com/go-chi/chi/v5"
	httpSwagger "github.com/swaggo/http-swagger"
)

func (s *Server) registerRoutes() {
	r := s.router

	// Health check
	r.Get("/health", s.handleHealthCheck)

	// Login
	r.Get("/login", s.handleLogin)
	r.Post("/login", s.handleLogin)
	r.Post("/logout", s.handleLogout)

	s.router.Route("/oauth", func(r chi.Router) {
		r.Get("/authorize", s.handleAuthorize)
		r.Post("/token", s.handleToken)
		r.Post("/introspect", s.handleIntrospect)
		r.Post("/revoke", s.handleRevoke)
	})

	// Swagger
	r.Get("/openapi/*", httpSwagger.Handler(
		httpSwagger.URL("http://localhost:8080/openapi.json"),
	))
	r.Get("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		http.ServeFile(w, r, "docs/swagger.json")
	})
}

// handleHealth godoc
// @Summary      Health check
// @Description  Returns OK if the service is up and running.
// @Tags         health
// @Produce      plain
// @Success      200 {string} string "OK"
// @Router      /health [get]
func (s *Server) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// temporary no-op
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// temporary no-op
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	// temporary no-op
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	// temporary no-op
}

func (s *Server) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	// temporary no-op
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	// temporary no-op
}
