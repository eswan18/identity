package httpserver

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"time"

	"github.com/eswan18/identity/internal/db"
	"github.com/google/uuid"
)

const authorizationCodeExpiresIn = 10 * time.Minute
const sessionExpiresIn = 24 * time.Hour

type Session struct {
	ID        string
	UserID    uuid.UUID
	ExpiresAt time.Time
}

// generateAuthorizationCode generates a new authorization code and stores it in the database
func (s *Server) generateAuthorizationCode(ctx context.Context, userID uuid.UUID, clientID uuid.UUID, redirectURI string, scope []string, codeChallenge string, codeChallengeMethod string) (string, error) {
	code, err := generateRandomString(32)
	if err != nil {
		return "", err
	}
	err = s.datastore.Q.InsertAuthorizationCode(ctx, db.InsertAuthorizationCodeParams{
		Code:                code,
		UserID:              userID,
		ClientID:            clientID,
		RedirectUri:         redirectURI,
		Scope:               scope,
		CodeChallenge:       sql.NullString{String: codeChallenge, Valid: codeChallenge != ""},
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
