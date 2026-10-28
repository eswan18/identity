package httpserver

import (
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

			// Validate the JWT (signature, issuer, expiry).
			claims, err := s.jwtGenerator.ValidateToken(accessToken, "")
			if err != nil {
				log.Printf("Admin auth: JWT validation failed: %v", err)
				s.writeAdminError(w, http.StatusUnauthorized, "invalid_token", "Invalid or expired access token")
				return
			}

			// The admin API is identity's own, so it accepts only tokens issued
			// for identity itself: aud is exactly [issuer]. A token minted for
			// some other API is not a key to this one, whatever scopes it holds.
			if !isAudienceExactly(claims.Audience, s.config.JWTIssuer) {
				log.Printf("Admin auth: token audience %v is not this issuer", []string(claims.Audience))
				s.writeAdminError(w, http.StatusUnauthorized, "invalid_token", "Access token was not issued for this server")
				return
			}

			// Revocation check. Unlike everything above it, this needs the
			// database -- and being unable to reach it is not permission to
			// continue. liveAccessToken's contract is that callers fail closed;
			// this path previously did the opposite, allowing the request through
			// on any error other than ErrNoRows and so skipping revocation
			// entirely, on the most privileged surface in the service.
			if _, live, err := s.liveAccessToken(r.Context(), claims.ID); err != nil {
				log.Printf("Admin auth: %v", err)
				s.writeAdminError(w, http.StatusInternalServerError, "server_error", "Failed to verify token status")
				return
			} else if !live {
				s.writeAdminError(w, http.StatusUnauthorized, "invalid_token", "Token has been revoked or is invalid")
				return
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

// isAudienceExactly reports whether aud names want and nothing else. Tokens this
// service issues always carry exactly one audience, so anything else is not one
// of ours for this purpose.
func isAudienceExactly(aud []string, want string) bool {
	return len(aud) == 1 && aud[0] == want
}

// writeAdminError writes an OAuth2-format error response for admin endpoints
func (s *Server) writeAdminError(w http.ResponseWriter, statusCode int, errorCode, description string) {
	writeJSONError(w, statusCode, errorCode, description)
}
