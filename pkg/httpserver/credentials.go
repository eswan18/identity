package httpserver

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"

	"github.com/eswan18/identity/pkg/auth"
	"github.com/eswan18/identity/pkg/db"
	"github.com/google/uuid"
)

const authorizationCodeExpiresIn = 10 * time.Minute
const sessionExpiresIn = 24 * time.Hour
const accessTokenExpiresIn = 1 * time.Hour
const refreshTokenExpiresIn = 30 * 24 * time.Hour

// Sentinel errors for credential validation
var (
	ErrMissingCredentials = errors.New("username and password are required")
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrInternal           = errors.New("an error occurred")
)

// Sentinel errors for OAuth client validation
var (
	ErrInvalidClient      = errors.New("invalid client")
	ErrInvalidRedirectURI = errors.New("invalid redirect URI")
	ErrInvalidScope       = errors.New("invalid scope")
)

// validateOAuthClient validates that the client exists and the redirect URI and scopes are allowed.
// Returns the client on success. On failure, returns one of:
//   - ErrInvalidClient (client doesn't exist)
//   - ErrInvalidRedirectURI (redirect URI not in allowlist)
//   - ErrInvalidScope (requested scopes not allowed)
func (s *Server) validateOAuthClient(ctx context.Context, clientID, redirectURI string, scopes []string) (db.OauthClient, error) {
	client, err := s.datastore.Q.GetOAuthClientByClientID(ctx, clientID)
	if err != nil {
		log.Printf("validateOAuthClient: error getting client by client ID: %s\n", err)
		return db.OauthClient{}, ErrInvalidClient
	}
	if !slices.Contains(client.RedirectUris, redirectURI) {
		log.Printf("validateOAuthClient: redirect URI %s not in allowlist for client: %s\n", redirectURI, clientID)
		return db.OauthClient{}, ErrInvalidRedirectURI
	}
	if scopesAreAllowed, invalidScopes := containsAll(client.AllowedScopes, scopes); !scopesAreAllowed {
		log.Printf("validateOAuthClient: scopes %v not allowed for client: %s\n", invalidScopes, clientID)
		return db.OauthClient{}, fmt.Errorf("%w: scopes %v not allowed", ErrInvalidScope, invalidScopes)
	}
	return client, nil
}

// validateCredentials validates a username and password against the database.
// Returns the user on success. On failure, returns one of:
//   - ErrMissingCredentials (400)
//   - ErrInvalidCredentials (401)
//   - ErrInternal (500)
//
// Security: Always returns ErrInvalidCredentials for invalid username/password
// to prevent username enumeration attacks. The specific reason (user not found vs
// wrong password) is logged for debugging but not exposed to the client.
func (s *Server) validateCredentials(ctx context.Context, username, password string) (db.AuthUser, error) {
	if username == "" || password == "" {
		return db.AuthUser{}, ErrMissingCredentials
	}

	user, err := s.datastore.Q.GetUserByUsername(ctx, username)
	if err == sql.ErrNoRows {
		// User doesn't exist - log for debugging but return generic error to prevent enumeration
		log.Printf("validateCredentials: user not found: %s", username)
		return db.AuthUser{}, ErrInvalidCredentials
	}
	if err != nil {
		return db.AuthUser{}, ErrInternal
	}

	valid, err := auth.VerifyPassword(password, user.PasswordHash)
	if err != nil {
		log.Printf("validateCredentials: password verification error for user %s: %v", username, err)
		return db.AuthUser{}, ErrInternal
	}
	if !valid {
		// Wrong password - log for debugging but return generic error to prevent enumeration
		log.Printf("validateCredentials: invalid password for user: %s", username)
		return db.AuthUser{}, ErrInvalidCredentials
	}

	return user, nil
}

type Session struct {
	ID        string
	UserID    uuid.UUID
	ExpiresAt time.Time
}

type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int // seconds until access token expires
	Scope        []string
}

// normalizeCodeChallenge normalizes a base64url-encoded code challenge by removing padding.
// This ensures consistent storage and comparison per RFC 7636, which specifies base64url
// encoding without padding.
func normalizeCodeChallenge(challenge string) string {
	return strings.TrimRight(challenge, "=")
}

// generateAuthorizationCode generates a new authorization code and stores it in the database
func (s *Server) generateAuthorizationCode(ctx context.Context, userID uuid.UUID, clientID uuid.UUID, redirectURI string, scope []string, codeChallenge string, codeChallengeMethod string) (string, error) {
	code, err := generateRandomString(32)
	if err != nil {
		return "", err
	}
	// Normalize the code challenge by removing padding to ensure consistent storage per RFC 7636
	normalizedChallenge := ""
	if codeChallenge != "" {
		normalizedChallenge = normalizeCodeChallenge(codeChallenge)
	}
	err = s.datastore.Q.InsertAuthorizationCode(ctx, db.InsertAuthorizationCodeParams{
		Code:                code,
		UserID:              userID,
		ClientID:            clientID,
		RedirectUri:         redirectURI,
		Scope:               scope,
		CodeChallenge:       sql.NullString{String: normalizedChallenge, Valid: codeChallenge != ""},
		CodeChallengeMethod: sql.NullString{String: codeChallengeMethod, Valid: codeChallengeMethod != ""},
		ExpiresAt:           time.Now().Add(authorizationCodeExpiresIn),
	})
	if err != nil {
		return "", err
	}
	return code, nil
}

// generateRandomString generates a cryptographically secure random string of the given length
func generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// createSession creates a new session and stores it in the database
func (s *Server) createSession(ctx context.Context, userID uuid.UUID) (Session, error) {
	sessionId, err := generateRandomString(32)
	if err != nil {
		return Session{}, err
	}
	err = s.datastore.Q.CreateSession(ctx, db.CreateSessionParams{
		ID:        sessionId,
		UserID:    userID,
		ExpiresAt: time.Now().Add(sessionExpiresIn),
	})
	if err != nil {
		return Session{}, err
	}
	return Session{
		ID:        sessionId,
		UserID:    userID,
		ExpiresAt: time.Now().Add(sessionExpiresIn),
	}, nil
}

// generateTokens creates new access and refresh tokens and stores them in the database.
// Returns the token pair on success.
func (s *Server) generateTokens(ctx context.Context, clientID uuid.UUID, userID uuid.UUID, scope []string) (TokenPair, error) {
	// Fetch user information for JWT claims
	user, err := s.datastore.Q.GetUserByID(ctx, userID)
	if err != nil {
		return TokenPair{}, fmt.Errorf("failed to get user: %w", err)
	}

	// Fetch client information for audience
	client, err := s.datastore.Q.GetOAuthClientByID(ctx, clientID)
	if err != nil {
		return TokenPair{}, fmt.Errorf("failed to get client: %w", err)
	}
	if client.Audience == "" {
		return TokenPair{}, fmt.Errorf("client %s has no audience configured", client.ClientID)
	}

	// Generate JWT access token with client's audience
	accessToken, jti, err := s.jwtGenerator.GenerateAccessToken(
		userID.String(),
		user.Username,
		user.Email,
		client.Audience,
		scope,
		accessTokenExpiresIn,
	)
	if err != nil {
		return TokenPair{}, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := generateRandomString(32)
	if err != nil {
		return TokenPair{}, err
	}

	accessExpiresAt := time.Now().Add(accessTokenExpiresIn)
	refreshExpiresAt := time.Now().Add(refreshTokenExpiresIn)

	// Store token record in database
	// Note: Store JTI (JWT ID) in access_token column for audit/revocation tracking
	_, err = s.datastore.Q.InsertToken(ctx, db.InsertTokenParams{
		AccessToken:      sql.NullString{String: jti, Valid: true}, // Store JTI, not full JWT
		RefreshToken:     sql.NullString{String: refreshToken, Valid: true},
		UserID:           uuid.NullUUID{UUID: userID, Valid: userID != uuid.Nil},
		ClientID:         clientID,
		Scope:            scope,
		TokenType:        sql.NullString{String: "Bearer", Valid: true},
		ExpiresAt:        accessExpiresAt,
		RefreshExpiresAt: sql.NullTime{Time: refreshExpiresAt, Valid: true},
	})
	if err != nil {
		return TokenPair{}, err
	}

	return TokenPair{
		AccessToken:  accessToken, // Return full JWT to client
		RefreshToken: refreshToken,
		ExpiresIn:    int(accessTokenExpiresIn.Seconds()),
		Scope:        scope,
	}, nil
}
