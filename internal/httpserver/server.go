package httpserver

import (
	"context"
	"html/template"
	"net"
	"net/http"
	"time"

	"github.com/eswan18/identity/internal/config"
	"github.com/eswan18/identity/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type Server struct {
	config           *config.Config
	datastore        *store.Store
	router           chi.Router
	httpServer       *http.Server
	rateLimitStore   *rateLimitStore
	loginTemplate    *template.Template
	registerTemplate *template.Template
	errorTemplate    *template.Template
	successTemplate  *template.Template
}

func New(config *config.Config, datastore *store.Store) *Server {
	return newWithOptions(config, datastore, true)
}

func NewWithoutRateLimiting(config *config.Config, datastore *store.Store) *Server {
	return newWithOptions(config, datastore, false)
}

func newWithOptions(config *config.Config, datastore *store.Store, withRateLimiting bool) *Server {
	r := chi.NewRouter()
	loginTemplate := template.Must(template.ParseFiles(config.TemplatesDir + "/login.html"))
	registerTemplate := template.Must(template.ParseFiles(config.TemplatesDir + "/register.html"))
	errorTemplate := template.Must(template.ParseFiles(config.TemplatesDir + "/error.html"))
	successTemplate := template.Must(template.ParseFiles(config.TemplatesDir + "/success.html"))

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))
	s := &Server{
		config:           config,
		datastore:        datastore,
		router:           r,
		loginTemplate:    loginTemplate,
		registerTemplate: registerTemplate,
		errorTemplate:    errorTemplate,
		successTemplate:  successTemplate,
	}

	if withRateLimiting {
		// Create rate limit store and apply rate limiting to all routes
		// (20 requests per IP per minute - provides basic DDoS protection)
		rateLimitStore := newRateLimitStore()
		r.Use(rateLimitMiddleware(rateLimitStore, 20))
		s.rateLimitStore = rateLimitStore
	}

	s.registerRoutes()

	return s
}

// Router returns the server's router. This is useful for serverless deployments
// where you want to use the server's router directly instead of creating a new one.
func (s *Server) Router() chi.Router {
	return s.router
}

// IsListening checks if the server is listening on the configured address.
func (s *Server) IsListening() bool {
	if s.httpServer == nil {
		return false
	}
	conn, err := net.DialTimeout("tcp", s.config.HTTPAddress, 5*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

func (s *Server) Run() error {
	s.httpServer = &http.Server{
		Addr:    s.config.HTTPAddress,
		Handler: s.router,
	}
	return s.httpServer.ListenAndServe()
}

func (s *Server) Close() error {
	var err error
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if shutdownErr := s.httpServer.Shutdown(ctx); shutdownErr != nil {
			err = shutdownErr
		}
	}
	if s.rateLimitStore != nil {
		s.rateLimitStore.Stop()
	}
	return err
}
