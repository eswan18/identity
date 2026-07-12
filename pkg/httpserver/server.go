package httpserver

import (
	"context"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/eswan18/identity/pkg/avatar"
	"github.com/eswan18/identity/pkg/config"
	"github.com/eswan18/identity/pkg/email"
	"github.com/eswan18/identity/pkg/jwt"
	"github.com/eswan18/identity/pkg/storage"
	"github.com/eswan18/identity/pkg/store"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type Server struct {
	config         *config.Config
	datastore      *store.Store
	router         chi.Router
	httpServer     *http.Server
	cleanupCancel  context.CancelFunc
	rateLimitStore *rateLimitStore
	jwtGenerator   *jwt.Generator
	emailSender    email.Sender
	avatarService  *avatar.Service
}

func New(config *config.Config, datastore *store.Store, emailSender email.Sender, storageProvider storage.Storage) *Server {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	// NOTE: chi's middleware.RealIP is intentionally NOT used here. It
	// unconditionally trusts the client-supplied X-Forwarded-For/X-Real-IP
	// headers and rewrites r.RemoteAddr from them, which lets any client
	// spoof its apparent IP (e.g. to bypass rate limiting keyed on IP - see
	// getClientIP in ratelimit.go). We leave r.RemoteAddr as the actual TCP
	// peer address; the real client IP behind the Cloudflare Tunnel is
	// derived from the CF-Connecting-IP header in getClientIP, which
	// Cloudflare guarantees to overwrite (unlike XFF/X-Real-IP, which anyone
	// can set).
	// Security headers apply to every response; HSTS within them is gated on
	// isSecureContext so it is only ever sent when the service is actually reached
	// over HTTPS (see isSecureContext for why config.HTTPAddress can't be used here).
	r.Use(securityHeadersMiddleware(isSecureContext(config)))
	// requestLoggingMiddleware replaces chi's middleware.Logger, which logs the raw
	// RequestURI (including query string) verbatim. Password-reset and
	// email-verification links carry single-use secret tokens in a "token" query
	// parameter (see password_reset.go, email_verification.go); logging them verbatim
	// would put those secrets in access logs. requestLoggingMiddleware logs the same
	// method/path/status/duration fields but redacts sensitive query parameter values.
	r.Use(requestLoggingMiddleware)
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
		config:         config,
		datastore:      datastore,
		router:         r,
		rateLimitStore: rateLimitStore,
		jwtGenerator:   jwtGen,
		emailSender:    emailSender,
		avatarService:  avatar.NewService(storageProvider),
	}
	s.registerRoutes()

	return s
}

// isSecureContext reports whether the service is actually reached by clients over
// HTTPS (e.g. behind a TLS-terminating reverse proxy in production). It is used to
// gate anything that must never be sent/applied over plain HTTP: the session cookie's
// Secure attribute and the Strict-Transport-Security header.
//
// config.HTTPAddress cannot be used for this: it is just the local listen address
// passed to http.Server.Addr (e.g. ":8000"), so a prefix check like
// strings.HasPrefix(cfg.HTTPAddress, "https://") is always false, even in production
// behind TLS -- which is exactly the bug this fixes.
//
// config.JWTIssuer is the service's public base URL and is validated at startup to be
// a well-formed http(s) URL (see config.validateIssuerURL), so its scheme reliably
// reflects how the service is actually reached: "https://identity.example.com" in
// production, "http://localhost:8000" in local dev. That makes it a reliable,
// zero-new-config signal for "am I being served over HTTPS".
func isSecureContext(cfg *config.Config) bool {
	return strings.HasPrefix(cfg.JWTIssuer, "https://")
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

	// Launch the periodic expiry-cleanup worker (see cleanup.go) here, not in
	// New, so constructing a Server for tests never spawns background work.
	// cleanupCancel lets Close (or the deferred cancel below, once
	// ListenAndServe returns) stop the goroutine cleanly. In production, Run
	// blocks on ListenAndServe for the life of the process, so the worker
	// effectively runs until the process is killed and is cancelled as part
	// of an orderly Close/shutdown.
	cleanupCtx, cancel := context.WithCancel(context.Background())
	s.cleanupCancel = cancel
	defer cancel()
	go s.startCleanupWorker(cleanupCtx)

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
	if s.cleanupCancel != nil {
		s.cleanupCancel()
	}
	if s.rateLimitStore != nil {
		s.rateLimitStore.Stop()
	}
	return err
}

// isSecureContext reports whether this server instance is being served over HTTPS.
// See the package-level isSecureContext function for the reasoning behind the signal.
func (s *Server) isSecureContext() bool {
	return isSecureContext(s.config)
}

// ResetRateLimits clears all rate limiters (useful for testing)
func (s *Server) ResetRateLimits() {
	if s.rateLimitStore != nil {
		s.rateLimitStore.Reset()
	}
}
