package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

var router chi.Router

func init() {
	// Initialize router once
	router = chi.NewRouter()

	// Apply middleware (no rate limiting - Vercel has built-in DDoS protection)
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)

	// Get server instance and register routes using the shared method
	server := getServer()
	server.RegisterRoutes(router)
}

// Handler is the entry point for Vercel serverless functions
// Vercel will call this function for all requests
func Handler(w http.ResponseWriter, r *http.Request) {
	router.ServeHTTP(w, r)
}
