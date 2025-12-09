package httpserver

import (
	"html/template"
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
	loginTemplate    *template.Template
	registerTemplate *template.Template
	errorTemplate    *template.Template
	successTemplate  *template.Template
}

func New(config *config.Config, datastore *store.Store) *Server {
	r := chi.NewRouter()
	loginTemplate := template.Must(template.ParseFiles("templates/login.html"))
	registerTemplate := template.Must(template.ParseFiles("templates/register.html"))
	errorTemplate := template.Must(template.ParseFiles("templates/error.html"))
	successTemplate := template.Must(template.ParseFiles("templates/success.html"))

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
	s.registerRoutes()

	return s
}

func (s *Server) Run() error {
	return http.ListenAndServe(s.config.HTTPAddress, s.router)
}
