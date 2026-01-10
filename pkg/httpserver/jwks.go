package httpserver

import (
	"log"
	"net/http"
)

// HandleJWKS returns the public keys in JWKS format for JWT validation
func (s *Server) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	jwks, err := s.jwtGenerator.PublicKeyJWKS()
	if err != nil {
		log.Printf("Error generating JWKS: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600") // Cache for 1 hour
	w.Write(jwks)
}
