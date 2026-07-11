package httpserver

import (
	"database/sql"
	"log"
	"net/http"
	"time"

	"github.com/eswan18/identity/pkg/auth"
	"github.com/eswan18/identity/pkg/db"
	"github.com/eswan18/identity/pkg/mfa"
)

// MFASetupPageData holds the data needed to render the MFA setup page template.
type MFASetupPageData struct {
	Error           string
	Success         string
	QRCode          string // Base64-encoded PNG
	Secret          string // For manual entry
	ProvisioningURI string
	CSRFToken       string
}

// mfaEnrollmentExpiresIn is how long a pending enrollment secret remains valid.
const mfaEnrollmentExpiresIn = 10 * time.Minute

// renderMFASetupError renders the setup page with only an error message (no QR).
func (s *Server) renderMFASetupError(w http.ResponseWriter, r *http.Request, msg string) {
	if err := s.mfaSetupTemplate.Execute(w, MFASetupPageData{Error: msg, CSRFToken: s.ensureCSRFToken(w, r)}); err != nil {
		log.Printf("[ERROR] renderMFASetupError: Failed to render MFA setup page: %v", err)
	}
}

// renderMFASetupPage renders the setup page for a given server-stored secret,
// reconstructing the QR code and provisioning URI from that exact secret so the
// displayed QR always matches the secret that will be validated.
func (s *Server) renderMFASetupPage(w http.ResponseWriter, r *http.Request, username, secret, errMsg string) {
	key, err := mfa.KeyFromSecret(username, secret)
	if err != nil {
		log.Printf("[ERROR] renderMFASetupPage: Failed to rebuild TOTP key: %v", err)
		s.renderMFASetupError(w, r, "Failed to generate MFA setup. Please try again.")
		return
	}

	qrCode, err := mfa.GenerateQRCode(key)
	if err != nil {
		log.Printf("[ERROR] renderMFASetupPage: Failed to generate QR code: %v", err)
		s.renderMFASetupError(w, r, "Failed to generate QR code. Please try again.")
		return
	}

	if err := s.mfaSetupTemplate.Execute(w, MFASetupPageData{
		Error:           errMsg,
		QRCode:          qrCode,
		Secret:          secret,
		ProvisioningURI: mfa.GetProvisioningURI(key),
		CSRFToken:       s.ensureCSRFToken(w, r),
	}); err != nil {
		log.Printf("[ERROR] renderMFASetupPage: Failed to render MFA setup page: %v", err)
	}
}

// HandleMFASetupGet displays the MFA setup page with QR code.
func (s *Server) HandleMFASetupGet(w http.ResponseWriter, r *http.Request) {
	user, err := s.getUserFromSession(r)
	if err != nil {
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}

	// Check if MFA is already enabled
	if user.MfaEnabled {
		http.Redirect(w, r, "/oauth/account-settings", http.StatusFound)
		return
	}

	// Generate a new TOTP secret
	key, err := mfa.GenerateSecret(user.Username)
	if err != nil {
		log.Printf("[ERROR] HandleMFASetupGet: Failed to generate TOTP secret: %v", err)
		s.renderMFASetupError(w, r, "Failed to generate MFA secret. Please try again.")
		return
	}
	secret := mfa.GetSecret(key)

	// Persist the pending secret server-side, keyed to the user, so that the POST
	// validates the submitted code against a secret the client can neither choose
	// nor observe. The secret is never sent to the browser as a form value.
	if err := s.datastore.Q.CreateMFAEnrollmentPending(r.Context(), db.CreateMFAEnrollmentPendingParams{
		UserID:    user.ID,
		Secret:    secret,
		ExpiresAt: time.Now().Add(mfaEnrollmentExpiresIn),
	}); err != nil {
		log.Printf("[ERROR] HandleMFASetupGet: Failed to store pending MFA secret: %v", err)
		s.renderMFASetupError(w, r, "Failed to start MFA setup. Please try again.")
		return
	}

	s.renderMFASetupPage(w, r, user.Username, secret, "")
}

// HandleMFASetupPost verifies the TOTP code and enables MFA.
func (s *Server) HandleMFASetupPost(w http.ResponseWriter, r *http.Request) {
	user, err := s.getUserFromSession(r)
	if err != nil {
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}

	// Check if MFA is already enabled
	if user.MfaEnabled {
		http.Redirect(w, r, "/oauth/account-settings", http.StatusFound)
		return
	}

	code := r.FormValue("code")

	// Load the pending secret from server-side storage (NOT the form). This is the
	// only secret we will validate against or enable.
	pending, err := s.datastore.Q.GetMFAEnrollmentPending(r.Context(), user.ID)
	if err != nil {
		// No valid pending secret: enrollment was never started, or it expired while
		// the user entered their code. Send them back to GET to start fresh so a new
		// secret and QR are generated together.
		s.debugf("HandleMFASetupPost: No valid pending MFA secret for user %s: %v", user.Username, err)
		http.Redirect(w, r, "/oauth/mfa-setup", http.StatusFound)
		return
	}

	if code == "" {
		s.renderMFASetupPage(w, r, user.Username, pending.Secret, "Please enter the verification code from your authenticator app.")
		return
	}

	// Validate the TOTP code against the server-stored secret.
	if !mfa.ValidateCode(pending.Secret, code) {
		// Re-render using the SAME server-stored secret so the displayed QR and the
		// secret being validated stay consistent across retries.
		s.renderMFASetupPage(w, r, user.Username, pending.Secret, "Invalid verification code. Please try again.")
		return
	}

	// Enable MFA for the user using the server-stored secret.
	if err := s.datastore.Q.EnableMFA(r.Context(), db.EnableMFAParams{
		ID:        user.ID,
		MfaSecret: sql.NullString{String: pending.Secret, Valid: true},
	}); err != nil {
		log.Printf("[ERROR] HandleMFASetupPost: Failed to enable MFA: %v", err)
		s.renderMFASetupPage(w, r, user.Username, pending.Secret, "Failed to enable MFA. Please try again.")
		return
	}

	// Consume the pending enrollment secret (single use).
	if err := s.datastore.Q.DeleteMFAEnrollmentPending(r.Context(), user.ID); err != nil {
		log.Printf("[ERROR] HandleMFASetupPost: Failed to delete pending MFA secret: %v", err)
	}

	s.debugf("HandleMFASetupPost: MFA enabled for user: %s", user.Username)

	// Redirect to account settings with success message
	http.Redirect(w, r, "/oauth/account-settings?mfa_enabled=true", http.StatusFound)
}

// HandleMFADisablePost disables MFA for the user.
func (s *Server) HandleMFADisablePost(w http.ResponseWriter, r *http.Request) {
	user, err := s.getUserFromSession(r)
	if err != nil {
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}

	// Check if MFA is enabled
	if !user.MfaEnabled {
		http.Redirect(w, r, "/oauth/account-settings", http.StatusFound)
		return
	}

	password := r.FormValue("password")
	code := r.FormValue("code")

	// Validate password
	if password == "" {
		s.renderAccountSettings(w, r, AccountSettingsPageData{
			Username:   user.Username,
			Email:      user.Email,
			MfaEnabled: user.MfaEnabled,
			Error:      "Password is required to disable MFA",
		})
		return
	}

	valid, err := auth.VerifyPassword(password, user.PasswordHash)
	if err != nil {
		log.Printf("[ERROR] HandleMFADisablePost: Failed to verify password: %v", err)
		s.renderAccountSettings(w, r, AccountSettingsPageData{
			Username:   user.Username,
			Email:      user.Email,
			MfaEnabled: user.MfaEnabled,
			Error:      "An error occurred",
		})
		return
	}
	if !valid {
		w.WriteHeader(http.StatusUnauthorized)
		s.renderAccountSettings(w, r, AccountSettingsPageData{
			Username:   user.Username,
			Email:      user.Email,
			MfaEnabled: user.MfaEnabled,
			Error:      "Password is incorrect",
		})
		return
	}

	// Validate MFA code
	if code == "" || !user.MfaSecret.Valid {
		s.renderAccountSettings(w, r, AccountSettingsPageData{
			Username:   user.Username,
			Email:      user.Email,
			MfaEnabled: user.MfaEnabled,
			Error:      "MFA code is required to disable MFA",
		})
		return
	}

	if !mfa.ValidateCode(user.MfaSecret.String, code) {
		w.WriteHeader(http.StatusUnauthorized)
		s.renderAccountSettings(w, r, AccountSettingsPageData{
			Username:   user.Username,
			Email:      user.Email,
			MfaEnabled: user.MfaEnabled,
			Error:      "Invalid MFA code",
		})
		return
	}

	// Disable MFA
	err = s.datastore.Q.DisableMFA(r.Context(), user.ID)
	if err != nil {
		log.Printf("[ERROR] HandleMFADisablePost: Failed to disable MFA: %v", err)
		s.renderAccountSettings(w, r, AccountSettingsPageData{
			Username:   user.Username,
			Email:      user.Email,
			MfaEnabled: user.MfaEnabled,
			Error:      "Failed to disable MFA. Please try again.",
		})
		return
	}

	s.debugf("HandleMFADisablePost: MFA disabled for user: %s", user.Username)

	// Redirect to account settings with success message
	http.Redirect(w, r, "/oauth/account-settings?mfa_disabled=true", http.StatusFound)
}
