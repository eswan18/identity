package httpserver

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/eswan18/identity/pkg/auth"
	"github.com/eswan18/identity/pkg/db"
	jwtpkg "github.com/eswan18/identity/pkg/jwt"
	"github.com/eswan18/identity/pkg/redirecturi"
	"github.com/google/uuid"
)

const authorizationCodeExpiresIn = 10 * time.Minute
const sessionExpiresIn = 24 * time.Hour
const accessTokenExpiresIn = 1 * time.Hour
const refreshTokenExpiresIn = 30 * 24 * time.Hour
const serviceAccountTokenExpiresIn = 15 * time.Minute

// Sentinel errors for credential validation
var (
	ErrMissingCredentials = errors.New("username and password are required")
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrAccountDeactivated = errors.New("account deactivated")
	ErrInternal           = errors.New("an error occurred")
)

// Sentinel errors for OAuth client validation
var (
	ErrInvalidClient      = errors.New("invalid client")
	ErrInvalidRedirectURI = errors.New("invalid redirect URI")
)

// ErrConfidentialClientRequired is returned when an endpoint that requires a fully
// authenticated confidential client (e.g. introspection, revocation) is called by a
// public client that only supplied a client_id.
var ErrConfidentialClientRequired = errors.New("client authentication required")

// ErrClientLookupFailed reports that the client could not be looked up at all,
// as opposed to being looked up and rejected. Callers must not answer
// invalid_client for it: that is a verdict on the caller's credentials, and the
// credentials were never reached. Because client authentication runs before any
// grant handler, conflating the two meant a database outage told every client
// its credentials were bad.
var ErrClientLookupFailed = errors.New("client lookup failed")

// authenticateClient extracts client credentials from the request using either
// client_secret_post (form values) or client_secret_basic (Authorization header),
// looks up the client, and verifies the secret for confidential clients.
func (s *Server) authenticateClient(r *http.Request) (db.OauthClient, error) {
	clientID, clientSecret := parseClientCredentials(r)

	client, err := s.datastore.Q.GetOAuthClientByClientID(r.Context(), clientID)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return db.OauthClient{}, fmt.Errorf("%w: %w", ErrClientLookupFailed, err)
		}
		return db.OauthClient{}, fmt.Errorf("invalid client: %w", err)
	}

	if client.IsConfidential {
		// The stored secret is a hex-encoded SHA-256 hash; hash the presented
		// secret the same way and compare in constant time.
		if !client.ClientSecret.Valid || !auth.ClientSecretMatches(client.ClientSecret.String, clientSecret) {
			return db.OauthClient{}, errors.New("invalid client credentials")
		}
	}

	return client, nil
}

// requireConfidentialClient is the pure decision logic behind authenticateConfidentialClient:
// given the result of authenticateClient, it additionally rejects clients that are not
// confidential. It's split out from authenticateConfidentialClient so it can be unit tested
// without a database.
func requireConfidentialClient(client db.OauthClient, err error) (db.OauthClient, error) {
	if err != nil {
		return db.OauthClient{}, err
	}
	if !client.IsConfidential {
		return db.OauthClient{}, ErrConfidentialClientRequired
	}
	return client, nil
}

// authenticateConfidentialClient behaves like authenticateClient, but additionally requires
// that the caller be a confidential client that has presented a valid client_secret.
//
// authenticateClient intentionally lets public clients through with just a client_id (no
// secret) so that the token endpoint can keep supporting the authorization_code + PKCE flow
// (RFC 7636), where public clients (e.g. SPAs, mobile apps) have no client_secret to present.
// That's correct for /oauth/token, but it's NOT sufficient for endpoints where RFC 7662 §2.1
// (introspection) and RFC 7009 §2.1 (revocation) require the caller itself to authenticate:
// allowing a bare client_id through would let anyone who knows (or guesses) a registered
// client_id probe token validity or revoke arbitrary tokens.
//
// This helper adds that stricter requirement at the call site, without changing
// authenticateClient's contract or behavior for the token/refresh endpoints.
func (s *Server) authenticateConfidentialClient(r *http.Request) (db.OauthClient, error) {
	client, err := s.authenticateClient(r)
	return requireConfidentialClient(client, err)
}

// parseClientCredentials extracts client_id and client_secret from the request.
// It checks the Authorization header for Basic auth first (client_secret_basic),
// then falls back to form values (client_secret_post).
func parseClientCredentials(r *http.Request) (clientID, clientSecret string) {
	if username, password, ok := r.BasicAuth(); ok {
		return username, password
	}
	return r.FormValue("client_id"), r.FormValue("client_secret")
}

// validateOAuthClientRedirect validates that the client exists and the redirect URI is allowed.
// This is used early in the authorize flow to establish whether we can safely redirect errors
// back to the client. Returns the client on success. On failure, returns one of:
//   - ErrInvalidClient (client doesn't exist)
//   - ErrInvalidRedirectURI (redirect URI not in allowlist)
func (s *Server) validateOAuthClientRedirect(ctx context.Context, clientID, redirectURI string) (db.OauthClient, error) {
	client, err := s.datastore.Q.GetOAuthClientByClientID(ctx, clientID)
	if err != nil {
		log.Printf("validateOAuthClientRedirect: error getting client by client ID: %s\n", err)
		return db.OauthClient{}, ErrInvalidClient
	}
	if !redirectURIAllowed(client.RedirectUris, redirectURI) {
		log.Printf("validateOAuthClientRedirect: redirect URI %s not in allowlist for client: %s\n", redirectURI, clientID)
		// The breadth guard on wildcard entries binds at request time (see
		// pkg/redirecturi), so an entry registered before the rules tightened is
		// refused outright -- which looks exactly like "the candidate didn't
		// match" in the line above. Name any unusable entry and why, so a preview
		// environment that stopped working is diagnosable from the logs alone.
		for _, entryErr := range redirecturi.InvalidWildcardEntries(client.RedirectUris) {
			log.Printf("validateOAuthClientRedirect: client %s has a registered wildcard entry that can never match: %v", clientID, entryErr)
		}
		return db.OauthClient{}, ErrInvalidRedirectURI
	}
	return client, nil
}

// validateCredentialsIncludingInactive validates a username and password against the database,
// including deactivated users. This is used for direct login to the account settings page,
// where deactivated users should still be able to log in.
func (s *Server) validateCredentialsIncludingInactive(ctx context.Context, username, password string) (db.AuthUser, error) {
	return s.doValidateCredentials(ctx, username, password, s.datastore.Q.GetUserByUsernameIncludingInactive)
}

// doValidateCredentials is the shared implementation for credential validation.
// The getUserByUsername parameter selects which DB query to use (active-only vs all users).
func (s *Server) doValidateCredentials(ctx context.Context, username, password string, getUserByUsername func(context.Context, string) (db.AuthUser, error)) (db.AuthUser, error) {
	if username == "" || password == "" {
		return db.AuthUser{}, ErrMissingCredentials
	}

	user, err := getUserByUsername(ctx, username)
	if err == sql.ErrNoRows {
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
	IDToken      string // OIDC ID token, present when openid scope is requested
	ExpiresIn    int    // seconds until access token expires
	Scope        []string
}

// normalizeCodeChallenge normalizes a base64url-encoded code challenge by removing padding.
// This ensures consistent storage and comparison per RFC 7636, which specifies base64url
// encoding without padding.
func normalizeCodeChallenge(challenge string) string {
	return strings.TrimRight(challenge, "=")
}

// generateAuthorizationCode generates a new authorization code and stores it in the database
func (s *Server) generateAuthorizationCode(ctx context.Context, userID uuid.UUID, clientID uuid.UUID, redirectURI string, scope []string, codeChallenge string, codeChallengeMethod string, nonce string) (string, error) {
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
		Nonce:               sql.NullString{String: nonce, Valid: nonce != ""},
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

// tokenAudience is the aud of an access token issued for resource: the
// resource's URI, or identity's own issuer when there is none (a token for
// identity itself, e.g. userinfo or the admin API). The URI is used exactly as
// stored -- "ethanswan:fitness" is a live audience a resource server compares
// byte for byte.
func (s *Server) tokenAudience(resource sql.NullString) string {
	if resource.Valid {
		return resource.String
	}
	return s.config.JWTIssuer
}

// storedResource is what a token row records as the resource it was issued
// for: the aud itself, so the issuer for a token for identity itself.
//
// This code never stores NULL, so a row says exactly which aud it was minted
// with. (It had to while migration 000012's oauth_tokens_fill_resource trigger
// existed: that filled a NULL from the client's current default, and would have
// re-pointed a token for identity itself at whatever default the client had
// gained. 000014 dropped the trigger; NULL now appears only on rows from before
// 000012, and tokenAudience reads it as the issuer.)
func (s *Server) storedResource(resource sql.NullString) sql.NullString {
	return sql.NullString{String: s.tokenAudience(resource), Valid: true}
}

// generateTokens creates new access and refresh tokens and stores them in the database.
// Returns the token pair on success.
//
// resource is what the token is for, and becomes its aud (see tokenAudience).
// The aud is recorded on the token row (see storedResource), so a refresh
// reissues for the same audience instead of re-reading the client's default,
// which may since have changed. The caller decides it: the client's default
// resource at code exchange, the stored resource at refresh.
//
// family is the refresh-token family the row joins (a new one at code exchange,
// the presented token's at refresh); the refresh token expires no later than
// the family's absolute lifetime allows (see refresh_families.go).
func (s *Server) generateTokens(ctx context.Context, clientID uuid.UUID, userID uuid.UUID, scope []string, nonce string, resource sql.NullString, family uuid.UUID) (TokenPair, error) {
	// Fetch user information for JWT claims
	user, err := s.datastore.Q.GetUserByID(ctx, userID)
	if err != nil {
		return TokenPair{}, fmt.Errorf("failed to get user: %w", err)
	}

	// The public client_id goes in the access token's client_id claim and the
	// ID token's aud.
	client, err := s.datastore.Q.GetOAuthClientByID(ctx, clientID)
	if err != nil {
		return TokenPair{}, fmt.Errorf("failed to get client: %w", err)
	}

	accessToken, jti, err := s.jwtGenerator.GenerateAccessToken(
		userID.String(),
		user.Username,
		user.Email,
		s.tokenAudience(resource),
		client.ClientID,
		user.EmailVerified,
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

	now := time.Now()
	accessExpiresAt := now.Add(accessTokenExpiresIn)
	refreshExpiresAt := refreshTokenExpiry(family, now)

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
		Resource:         s.storedResource(resource),
		FamilyID:         uuid.NullUUID{UUID: family, Valid: true},
	})
	if err != nil {
		return TokenPair{}, err
	}

	// Generate OIDC ID token when openid scope is requested
	var idToken string
	if slices.Contains(scope, "openid") {
		idClaims := jwtpkg.IDTokenClaims{Nonce: nonce}
		if slices.Contains(scope, "email") {
			idClaims.Email = user.Email
			idClaims.EmailVerified = &user.EmailVerified
		}
		if slices.Contains(scope, "profile") {
			idClaims.Username = user.Username
			if user.GivenName.Valid {
				idClaims.GivenName = user.GivenName.String
			}
			if user.FamilyName.Valid {
				idClaims.FamilyName = user.FamilyName.String
			}
			if user.Picture.Valid {
				idClaims.Picture = user.Picture.String
			}
		}
		idToken, err = s.jwtGenerator.GenerateIDToken(
			userID.String(),
			client.ClientID,
			accessToken,
			idClaims,
			accessTokenExpiresIn,
		)
		if err != nil {
			return TokenPair{}, fmt.Errorf("failed to generate ID token: %w", err)
		}
	}

	return TokenPair{
		AccessToken:  accessToken, // Return full JWT to client
		RefreshToken: refreshToken,
		IDToken:      idToken,
		ExpiresIn:    int(accessTokenExpiresIn.Seconds()),
		Scope:        scope,
	}, nil
}

// generateServiceAccountTokens creates an access token for service accounts (client credentials grant).
// No user is involved - the client authenticates as itself. No refresh token is issued per OAuth2 spec.
// The token is for the client's default resource, or for identity itself (aud =
// issuer, which the admin API requires) when the client has none.
func (s *Server) generateServiceAccountTokens(ctx context.Context, client db.OauthClient, scope []string) (TokenPair, error) {
	resource := client.DefaultResource

	// Generate JWT access token with client_id as subject
	accessToken, jti, err := s.jwtGenerator.GenerateServiceAccountToken(
		client.ClientID,
		s.tokenAudience(resource),
		scope,
		serviceAccountTokenExpiresIn,
	)
	if err != nil {
		return TokenPair{}, fmt.Errorf("failed to generate access token: %w", err)
	}

	accessExpiresAt := time.Now().Add(serviceAccountTokenExpiresIn)

	// Store token record in database (no refresh token, null user_id)
	_, err = s.datastore.Q.InsertToken(ctx, db.InsertTokenParams{
		AccessToken:      sql.NullString{String: jti, Valid: true},
		RefreshToken:     sql.NullString{Valid: false}, // No refresh token per OAuth spec
		UserID:           uuid.NullUUID{Valid: false},  // No user for service accounts
		ClientID:         client.ID,
		Scope:            scope,
		TokenType:        sql.NullString{String: "Bearer", Valid: true},
		ExpiresAt:        accessExpiresAt,
		RefreshExpiresAt: sql.NullTime{Valid: false}, // No refresh token
		Resource:         s.storedResource(resource),
	})
	if err != nil {
		return TokenPair{}, err
	}

	return TokenPair{
		AccessToken:  accessToken,
		RefreshToken: "", // Empty per OAuth spec for client_credentials
		ExpiresIn:    int(serviceAccountTokenExpiresIn.Seconds()),
		Scope:        scope,
	}, nil
}
