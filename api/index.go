package api

import (
	"net/http"
)

var handler http.Handler

func init() {
	// Get server instance and use its router directly
	// The server's router already has all routes registered and middleware applied
	server := getServer()
	handler = server.Router()
}

// Handler is the entry point for Vercel serverless functions
// Vercel will call this function for all requests
func Handler(w http.ResponseWriter, r *http.Request) {
	handler.ServeHTTP(w, r)
}
