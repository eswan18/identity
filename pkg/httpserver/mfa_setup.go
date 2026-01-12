package httpserver

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/eswan18/identity/pkg/auth"
	"github.com/eswan18/identity/pkg/db"
	"github.com/eswan18/identity/pkg/mfa"
)

// MFASetupPageData holds the data needed to render the MFA setup page template.
type MFASetupPageData struct {
	Error          string
	Success        string
	QRCode         string // Base64-encoded PNG
	Secret         string // For manual entry
	ProvisioningURI string
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
		s.mfaSetupTemplate.Execute(w, MFASetupPageData{
			Error: "Failed to generate MFA secret. Please try again.",
		})
		return
	}

	// Generate QR code
	qrCode, err := mfa.GenerateQRCode(key)
	if err != nil {
		log.Printf("[ERROR] HandleMFASetupGet: Failed to generate QR code: %v", err)
		s.mfaSetupTemplate.Execute(w, MFASetupPageData{
			Error: "Failed to generate QR code. Please try again.",
		})
		return
	}

	// Store the secret temporarily in session storage
	// For simplicity, we'll include it as a hidden field (encrypted would be better)
	s.mfaSetupTemplate.Execute(w, MFASetupPageData{
		QRCode:          qrCode,
		Secret:          mfa.GetSecret(key),
		ProvisioningURI: mfa.GetProvisioningURI(key),
	})
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

	secret := r.FormValue("secret")
	code := r.FormValue("code")

	if secret == "" || code == "" {
		s.mfaSetupTemplate.Execute(w, MFASetupPageData{
			Error:  "Please enter the verification code from your authenticator app.",
			Secret: secret,
		})
		return
	}

	// Validate the TOTP code
	if !mfa.ValidateCode(secret, code) {
		// Regenerate QR code for the same secret
		key, _ := mfa.GenerateSecret(user.Username)
		qrCode, _ := mfa.GenerateQRCode(key)

		s.mfaSetupTemplate.Execute(w, MFASetupPageData{
			Error:           "Invalid verification code. Please try again.",
			QRCode:          qrCode,
			Secret:          secret,
			ProvisioningURI: mfa.GetProvisioningURI(key),
		})
		return
	}

	// Enable MFA for the user
	err = s.datastore.Q.EnableMFA(r.Context(), db.EnableMFAParams{
		ID:        user.ID,
		MfaSecret: sql.NullString{String: secret, Valid: true},
	})
	if err != nil {
		log.Printf("[ERROR] HandleMFASetupPost: Failed to enable MFA: %v", err)
		s.mfaSetupTemplate.Execute(w, MFASetupPageData{
			Error:  "Failed to enable MFA. Please try again.",
			Secret: secret,
		})
		return
	}

	log.Printf("[DEBUG] HandleMFASetupPost: MFA enabled for user: %s", user.Username)

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
		s.accountSettingsTemplate.Execute(w, AccountSettingsPageData{
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
		s.accountSettingsTemplate.Execute(w, AccountSettingsPageData{
			Username:   user.Username,
			Email:      user.Email,
			MfaEnabled: user.MfaEnabled,
			Error:      "An error occurred",
		})
		return
	}
	if !valid {
		w.WriteHeader(http.StatusUnauthorized)
		s.accountSettingsTemplate.Execute(w, AccountSettingsPageData{
			Username:   user.Username,
			Email:      user.Email,
			MfaEnabled: user.MfaEnabled,
			Error:      "Password is incorrect",
		})
		return
	}

	// Validate MFA code
	if code == "" || !user.MfaSecret.Valid {
		s.accountSettingsTemplate.Execute(w, AccountSettingsPageData{
			Username:   user.Username,
			Email:      user.Email,
			MfaEnabled: user.MfaEnabled,
			Error:      "MFA code is required to disable MFA",
		})
		return
	}

	if !mfa.ValidateCode(user.MfaSecret.String, code) {
		w.WriteHeader(http.StatusUnauthorized)
		s.accountSettingsTemplate.Execute(w, AccountSettingsPageData{
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
		s.accountSettingsTemplate.Execute(w, AccountSettingsPageData{
			Username:   user.Username,
			Email:      user.Email,
			MfaEnabled: user.MfaEnabled,
			Error:      "Failed to disable MFA. Please try again.",
		})
		return
	}

	log.Printf("[DEBUG] HandleMFADisablePost: MFA disabled for user: %s", user.Username)

	// Redirect to account settings with success message
	http.Redirect(w, r, "/oauth/account-settings?mfa_disabled=true", http.StatusFound)
}
