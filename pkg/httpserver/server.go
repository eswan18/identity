package httpserver

import (
	"context"
	"html/template"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/eswan18/identity/pkg/config"
	"github.com/eswan18/identity/pkg/email"
	"github.com/eswan18/identity/pkg/jwt"
	"github.com/eswan18/identity/pkg/store"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type Server struct {
	config                  *config.Config
	datastore               *store.Store
	router                  chi.Router
	httpServer              *http.Server
	rateLimitStore          *rateLimitStore
	jwtGenerator            *jwt.Generator
	emailSender             email.Sender
	loginTemplate           *template.Template
	registerTemplate        *template.Template
	errorTemplate           *template.Template
	successTemplate         *template.Template
	accountSettingsTemplate *template.Template
	changePasswordTemplate  *template.Template
	changeUsernameTemplate  *template.Template
	changeEmailTemplate     *template.Template
	mfaTemplate             *template.Template
	mfaSetupTemplate        *template.Template
	forgotPasswordTemplate  *template.Template
	resetPasswordTemplate   *template.Template
}

func New(config *config.Config, datastore *store.Store, emailSender email.Sender) *Server {
	r := chi.NewRouter()
	loginTemplate := template.Must(template.ParseFiles(config.TemplatesDir + "/login.html"))
	registerTemplate := template.Must(template.ParseFiles(config.TemplatesDir + "/register.html"))
	errorTemplate := template.Must(template.ParseFiles(config.TemplatesDir + "/error.html"))
	successTemplate := template.Must(template.ParseFiles(config.TemplatesDir + "/success.html"))
	accountSettingsTemplate := template.Must(template.ParseFiles(config.TemplatesDir + "/account-settings.html"))
	changePasswordTemplate := template.Must(template.ParseFiles(config.TemplatesDir + "/change-password.html"))
	changeUsernameTemplate := template.Must(template.ParseFiles(config.TemplatesDir + "/change-username.html"))
	changeEmailTemplate := template.Must(template.ParseFiles(config.TemplatesDir + "/change-email.html"))
	mfaTemplate := template.Must(template.ParseFiles(config.TemplatesDir + "/mfa.html"))
	mfaSetupTemplate := template.Must(template.ParseFiles(config.TemplatesDir + "/mfa-setup.html"))
	forgotPasswordTemplate := template.Must(template.ParseFiles(config.TemplatesDir + "/forgot-password.html"))
	resetPasswordTemplate := template.Must(template.ParseFiles(config.TemplatesDir + "/reset-password.html"))

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	// Create rate limit store and apply rate limiting to all routes
	// (20 requests per IP per minute - provides basic DDoS protection)
	rateLimitStore := newRateLimitStore()
	r.Use(rateLimitMiddleware(rateLimitStore, 20))

	jwtGen, err := jwt.NewGenerator(
		config.JWTPrivateKey,
		config.JWTIssuer,
		"key-1",
	)
	if err != nil {
		log.Fatalf("Failed to initialize JWT generator: %v", err)
	}

	s := &Server{
		config:                  config,
		datastore:               datastore,
		router:                  r,
		rateLimitStore:          rateLimitStore,
		jwtGenerator:            jwtGen,
		emailSender:             emailSender,
		loginTemplate:           loginTemplate,
		registerTemplate:        registerTemplate,
		errorTemplate:           errorTemplate,
		successTemplate:         successTemplate,
		accountSettingsTemplate: accountSettingsTemplate,
		changePasswordTemplate:  changePasswordTemplate,
		changeUsernameTemplate:  changeUsernameTemplate,
		changeEmailTemplate:     changeEmailTemplate,
		mfaTemplate:             mfaTemplate,
		mfaSetupTemplate:        mfaSetupTemplate,
		forgotPasswordTemplate:  forgotPasswordTemplate,
		resetPasswordTemplate:   resetPasswordTemplate,
	}
	s.registerRoutes()

	return s
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

// ResetRateLimits clears all rate limiters (useful for testing)
func (s *Server) ResetRateLimits() {
	if s.rateLimitStore != nil {
		s.rateLimitStore.Reset()
	}
}
