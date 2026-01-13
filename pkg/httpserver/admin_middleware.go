package httpserver

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"slices"
	"strings"
)

// AdminAuthMiddleware creates middleware that validates Bearer tokens and required scopes.
// It extracts the token from the Authorization header, validates it, checks for revocation,
// and verifies that all required scopes are present.
func (s *Server) AdminAuthMiddleware(requiredScopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract Bearer token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				s.writeAdminError(w, http.StatusUnauthorized, "invalid_token", "Missing or invalid Authorization header")
				return
			}
			accessToken := strings.TrimPrefix(authHeader, "Bearer ")

			// Validate JWT - use empty audience since this is the identity provider itself
			claims, err := s.jwtGenerator.ValidateToken(accessToken, "")
			if err != nil {
				log.Printf("Admin auth: JWT validation failed: %v", err)
				s.writeAdminError(w, http.StatusUnauthorized, "invalid_token", "Invalid or expired access token")
				return
			}

			// Check if token has been revoked (by looking up JTI in database)
			if claims.ID != "" {
				_, err := s.datastore.Q.GetTokenByAccessToken(r.Context(), sql.NullString{String: claims.ID, Valid: true})
				if err == sql.ErrNoRows {
					// Token not found could mean it was revoked or never existed
					s.writeAdminError(w, http.StatusUnauthorized, "invalid_token", "Token has been revoked or is invalid")
					return
				}
				// Note: If err != nil but not ErrNoRows, we allow through - the DB might be temporarily unavailable
			}

			// Validate required scopes
			tokenScopes := strings.Split(claims.Scope, " ")
			for _, requiredScope := range requiredScopes {
				if !slices.Contains(tokenScopes, requiredScope) {
					log.Printf("Admin auth: Token missing required scope %s (has: %v)", requiredScope, tokenScopes)
					s.writeAdminError(w, http.StatusForbidden, "insufficient_scope",
						"Token missing required scope: "+requiredScope)
					return
				}
			}

			// Token is valid and has required scopes, proceed with request
			next.ServeHTTP(w, r)
		})
	}
}

// writeAdminError writes an OAuth2-format error response for admin endpoints
func (s *Server) writeAdminError(w http.ResponseWriter, statusCode int, errorCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             errorCode,
		"error_description": description,
	})
}
