package httpserver

import (
	"database/sql"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/eswan18/identity/pkg/db"
	"github.com/eswan18/identity/pkg/mfa"
	"github.com/google/uuid"
)

const mfaPendingExpiresIn = 5 * time.Minute

// MFAPageData holds the data needed to render the MFA verification page template.
type MFAPageData struct {
	Error     string
	PendingID string
}

// HandleMFAGet displays the MFA code entry form.
func (s *Server) HandleMFAGet(w http.ResponseWriter, r *http.Request) {
	pendingID := r.URL.Query().Get("pending")
	if pendingID == "" {
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}

	// Verify the pending MFA session exists and is valid
	_, err := s.datastore.Q.GetMFAPending(r.Context(), pendingID)
	if err != nil {
		log.Printf("[DEBUG] HandleMFAGet: Invalid or expired pending MFA session: %v", err)
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}

	s.mfaTemplate.Execute(w, MFAPageData{
		PendingID: pendingID,
	})
}

// HandleMFAPost validates the MFA code and completes the login flow.
func (s *Server) HandleMFAPost(w http.ResponseWriter, r *http.Request) {
	pendingID := r.FormValue("pending_id")
	code := r.FormValue("code")

	if pendingID == "" {
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}

	// Get the pending MFA session
	pending, err := s.datastore.Q.GetMFAPending(r.Context(), pendingID)
	if err != nil {
		log.Printf("[DEBUG] HandleMFAPost: Invalid or expired pending MFA session: %v", err)
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}

	// Get the user's MFA secret
	mfaStatus, err := s.datastore.Q.GetUserMFAStatus(r.Context(), pending.UserID)
	if err != nil {
		log.Printf("[ERROR] HandleMFAPost: Failed to get MFA status: %v", err)
		s.renderMFAError(w, http.StatusInternalServerError, "An error occurred", pendingID)
		return
	}

	if !mfaStatus.MfaEnabled || !mfaStatus.MfaSecret.Valid {
		log.Printf("[ERROR] HandleMFAPost: MFA not enabled for user")
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}

	// Validate the TOTP code
	if !mfa.ValidateCode(mfaStatus.MfaSecret.String, code) {
		log.Printf("[DEBUG] HandleMFAPost: Invalid MFA code for user: %v", pending.UserID)
		s.renderMFAError(w, http.StatusUnauthorized, "Invalid verification code", pendingID)
		return
	}

	// Delete the pending MFA session
	if err := s.datastore.Q.DeleteMFAPending(r.Context(), pendingID); err != nil {
		log.Printf("[ERROR] HandleMFAPost: Failed to delete pending MFA session: %v", err)
	}

	// Create authenticated session
	session, err := s.createSession(r.Context(), pending.UserID)
	if err != nil {
		log.Printf("[ERROR] HandleMFAPost: Failed to create session: %v", err)
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}

	// Update last login timestamp
	if err := s.datastore.Q.UpdateUserLastLogin(r.Context(), pending.UserID); err != nil {
		log.Printf("[ERROR] HandleMFAPost: Failed to update last login time: %v", err)
		// Non-fatal error - continue with login
	}

	// Set secure session cookie
	isSecure := strings.HasPrefix(s.config.HTTPAddress, "https://") || strings.Contains(s.config.HTTPAddress, ":443")
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    session.ID,
		Path:     "/",
		Expires:  session.ExpiresAt,
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteLaxMode,
	})

	// Check if this is a direct login (no OAuth flow)
	if !pending.ClientID.Valid || pending.ClientID.String == "" {
		log.Printf("[DEBUG] HandleMFAPost: Direct login, redirecting to account settings")
		http.Redirect(w, r, "/oauth/account-settings", http.StatusFound)
		return
	}

	// Continue with OAuth flow
	clientID := pending.ClientID.String
	redirectURI := pending.RedirectUri.String
	state := pending.State.String
	scope := pending.Scope
	codeChallenge := pending.CodeChallenge.String
	codeChallengeMethod := pending.CodeChallengeMethod.String

	// Validate OAuth client
	client, err := s.validateOAuthClient(r.Context(), clientID, redirectURI, scope)
	if err != nil {
		log.Printf("[ERROR] HandleMFAPost: OAuth client validation failed: %v", err)
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}

	if redirectURI == "" {
		http.Redirect(w, r, "/oauth/success", http.StatusFound)
		return
	}

	// Generate authorization code
	authorizationCode, err := s.generateAuthorizationCode(r.Context(), pending.UserID, client.ID, redirectURI, scope, codeChallenge, codeChallengeMethod)
	if err != nil {
		log.Printf("[ERROR] HandleMFAPost: Failed to generate authorization code: %v", err)
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}

	// Build redirect URL
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		log.Printf("[ERROR] HandleMFAPost: Failed to parse redirect URI: %v", err)
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}
	q := redirectURL.Query()
	q.Set("state", state)
	q.Set("code", authorizationCode)
	redirectURL.RawQuery = q.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// createMFAPendingSession creates a pending MFA session after password validation.
func (s *Server) createMFAPendingSession(r *http.Request, userID uuid.UUID, oauthParams LoginPageData) (string, error) {
	pendingID, err := generateRandomString(32)
	if err != nil {
		return "", err
	}

	params := db.CreateMFAPendingParams{
		ID:                  pendingID,
		UserID:              userID,
		ClientID:            sql.NullString{String: oauthParams.ClientID, Valid: oauthParams.ClientID != ""},
		RedirectUri:         sql.NullString{String: oauthParams.RedirectURI, Valid: oauthParams.RedirectURI != ""},
		State:               sql.NullString{String: oauthParams.State, Valid: oauthParams.State != ""},
		Scope:               oauthParams.Scope,
		CodeChallenge:       sql.NullString{String: oauthParams.CodeChallenge, Valid: oauthParams.CodeChallenge != ""},
		CodeChallengeMethod: sql.NullString{String: oauthParams.CodeChallengeMethod, Valid: oauthParams.CodeChallengeMethod != ""},
		ExpiresAt:           time.Now().Add(mfaPendingExpiresIn),
	}

	if err := s.datastore.Q.CreateMFAPending(r.Context(), params); err != nil {
		return "", err
	}

	return pendingID, nil
}

// renderMFAError renders the MFA page with an error message.
func (s *Server) renderMFAError(w http.ResponseWriter, statusCode int, errorMsg string, pendingID string) {
	w.WriteHeader(statusCode)
	s.mfaTemplate.Execute(w, MFAPageData{
		Error:     errorMsg,
		PendingID: pendingID,
	})
}
