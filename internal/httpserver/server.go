package httpserver

import (
	"html/template"
	"net/http"
	"time"

	"github.com/eswan18/fcast-auth/internal/config"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type Server struct {
	config        *config.Config
	router        chi.Router
	loginTemplate *template.Template
	errorTemplate *template.Template
}

func New(config *config.Config) *Server {
	r := chi.NewRouter()
	loginTemplate := template.Must(template.ParseFiles("templates/login.html"))
	errorTemplate := template.Must(template.ParseFiles("templates/error.html"))

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Use(middleware.Timeout(60 * time.Second))

	s := &Server{
		config:        config,
		router:        r,
		loginTemplate: loginTemplate,
		errorTemplate: errorTemplate,
	}
	s.registerRoutes()

	return s
}

func (s *Server) Run() error {
	return http.ListenAndServe(":"+s.config.Port, s.router)
}
