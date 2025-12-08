package httpserver

import (
	"net/http"

	"github.com/go-chi/chi/v5"
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
}

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
