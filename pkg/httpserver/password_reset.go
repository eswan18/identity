package httpserver

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/eswan18/identity/pkg/auth"
	"github.com/eswan18/identity/pkg/db"
	"github.com/eswan18/identity/pkg/email"
)

const (
	passwordResetTokenTTL = 1 * time.Hour
	passwordResetTokenLen = 32 // bytes
)

// generateResetToken generates a cryptographically secure random token
// and returns both the raw token (for the email link) and its SHA-256 hash (for storage).
func generateResetToken() (rawToken, tokenHash string, err error) {
	tokenBytes := make([]byte, passwordResetTokenLen)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate random token: %w", err)
	}

	rawToken = base64.URLEncoding.EncodeToString(tokenBytes)
	tokenHash = hashToken(rawToken)
	return rawToken, tokenHash, nil
}

// HandleForgotPasswordGet godoc
// @Summary      Show forgot password page
// @Description  Displays the forgot password form
// @Tags         authentication
// @Produce      html
// @Success      200 {string} string "HTML forgot password page"
// @Router       /forgot-password [get]
func (s *Server) HandleForgotPasswordGet(w http.ResponseWriter, r *http.Request) {
	s.forgotPasswordTemplate.Execute(w, ForgotPasswordPageData{})
}

// HandleForgotPasswordPost godoc
// @Summary      Request password reset
// @Description  Sends a password reset email if the account exists
// @Tags         authentication
// @Accept       application/x-www-form-urlencoded
// @Produce      html
// @Param        email formData string true "Email address"
// @Success      200 {string} string "HTML forgot password page with success message"
// @Router       /forgot-password [post]
func (s *Server) HandleForgotPasswordPost(w http.ResponseWriter, r *http.Request) {
	emailAddr := r.FormValue("email")

	if emailAddr == "" {
		w.WriteHeader(http.StatusBadRequest)
		s.forgotPasswordTemplate.Execute(w, ForgotPasswordPageData{
			Error: "Email address is required",
		})
		return
	}

	// Always show success message to prevent email enumeration
	successMsg := "If an account with that email exists, we've sent a password reset link."

	// Look up user by email
	user, err := s.datastore.Q.GetUserByEmail(r.Context(), emailAddr)
	if err != nil {
		// User not found - still show success message (no email enumeration)
		log.Printf("[DEBUG] HandleForgotPasswordPost: No user found for email %s", emailAddr)
		s.forgotPasswordTemplate.Execute(w, ForgotPasswordPageData{
			Success: successMsg,
		})
		return
	}

	// Generate token
	rawToken, tokenHash, err := generateResetToken()
	if err != nil {
		log.Printf("[ERROR] HandleForgotPasswordPost: Failed to generate token: %v", err)
		s.forgotPasswordTemplate.Execute(w, ForgotPasswordPageData{
			Error: "An error occurred. Please try again.",
		})
		return
	}

	// Store token hash in database
	expiresAt := time.Now().Add(passwordResetTokenTTL)
	err = s.datastore.Q.CreatePasswordResetToken(r.Context(), db.CreatePasswordResetTokenParams{
		UserID:    user.ID,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		log.Printf("[ERROR] HandleForgotPasswordPost: Failed to store token: %v", err)
		s.forgotPasswordTemplate.Execute(w, ForgotPasswordPageData{
			Error: "An error occurred. Please try again.",
		})
		return
	}

	// Send password reset email
	resetURL := fmt.Sprintf("%s/oauth/reset-password?token=%s", s.config.JWTIssuer, rawToken)
	err = s.emailSender.Send(r.Context(), email.Message{
		To:      emailAddr,
		Subject: "Reset Your Password",
		HTML: fmt.Sprintf(`
			<h2>Reset Your Password</h2>
			<p>You requested a password reset for your account. Click the link below to set a new password:</p>
			<p><a href="%s">Reset Password</a></p>
			<p>This link will expire in 1 hour.</p>
			<p>If you didn't request this, you can safely ignore this email.</p>
		`, resetURL),
		Text: fmt.Sprintf(`
Reset Your Password

You requested a password reset for your account. Visit the link below to set a new password:

%s

This link will expire in 1 hour.

If you didn't request this, you can safely ignore this email.
		`, resetURL),
	})
	if err != nil {
		log.Printf("[ERROR] HandleForgotPasswordPost: Failed to send email: %v", err)
		// Still show success to prevent enumeration, but log the error
	}

	log.Printf("[DEBUG] HandleForgotPasswordPost: Password reset email sent to %s", emailAddr)
	s.forgotPasswordTemplate.Execute(w, ForgotPasswordPageData{
		Success: successMsg,
	})
}

// HandleResetPasswordGet godoc
// @Summary      Show reset password page
// @Description  Displays the reset password form for users who clicked a reset link
// @Tags         authentication
// @Produce      html
// @Param        token query string true "Password reset token"
// @Success      200 {string} string "HTML reset password page"
// @Failure      400 {string} string "Invalid or expired token"
// @Router       /reset-password [get]
func (s *Server) HandleResetPasswordGet(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")

	if token == "" {
		w.WriteHeader(http.StatusBadRequest)
		s.resetPasswordTemplate.Execute(w, ResetPasswordPageData{
			Error: "Invalid password reset link.",
		})
		return
	}

	// Validate token exists and is not expired
	tokenHash := hashToken(token)
	_, err := s.datastore.Q.GetPasswordResetTokenByHash(r.Context(), tokenHash)
	if err != nil {
		log.Printf("[DEBUG] HandleResetPasswordGet: Invalid or expired token")
		w.WriteHeader(http.StatusBadRequest)
		s.resetPasswordTemplate.Execute(w, ResetPasswordPageData{
			Error: "This password reset link is invalid or has expired. Please request a new one.",
		})
		return
	}

	s.resetPasswordTemplate.Execute(w, ResetPasswordPageData{
		Token: token,
	})
}

// HandleResetPasswordPost godoc
// @Summary      Reset password
// @Description  Sets a new password using a valid reset token
// @Tags         authentication
// @Accept       application/x-www-form-urlencoded
// @Produce      html
// @Param        token            formData string true "Password reset token"
// @Param        new_password     formData string true "New password"
// @Param        confirm_password formData string true "Confirm new password"
// @Success      302 {string} string "Redirect to login page on success"
// @Failure      400 {string} string "Invalid token or password mismatch"
// @Router       /reset-password [post]
func (s *Server) HandleResetPasswordPost(w http.ResponseWriter, r *http.Request) {
	token := r.FormValue("token")
	newPassword := r.FormValue("new_password")
	confirmPassword := r.FormValue("confirm_password")

	// Validate required fields
	if token == "" {
		w.WriteHeader(http.StatusBadRequest)
		s.resetPasswordTemplate.Execute(w, ResetPasswordPageData{
			Error: "Invalid password reset link.",
		})
		return
	}

	if newPassword == "" || confirmPassword == "" {
		w.WriteHeader(http.StatusBadRequest)
		s.resetPasswordTemplate.Execute(w, ResetPasswordPageData{
			Error: "All fields are required.",
			Token: token,
		})
		return
	}

	if newPassword != confirmPassword {
		w.WriteHeader(http.StatusBadRequest)
		s.resetPasswordTemplate.Execute(w, ResetPasswordPageData{
			Error: "Passwords do not match.",
			Token: token,
		})
		return
	}

	// Validate and get token record first (need username for password validation)
	tokenHash := hashToken(token)
	tokenRecord, err := s.datastore.Q.GetPasswordResetTokenByHash(r.Context(), tokenHash)
	if err != nil {
		log.Printf("[DEBUG] HandleResetPasswordPost: Invalid or expired token")
		w.WriteHeader(http.StatusBadRequest)
		s.resetPasswordTemplate.Execute(w, ResetPasswordPageData{
			Error: "This password reset link is invalid or has expired. Please request a new one.",
		})
		return
	}

	// Validate password requirements
	if err := auth.ValidatePassword(newPassword, tokenRecord.Username); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		s.resetPasswordTemplate.Execute(w, ResetPasswordPageData{
			Error: err.Error(),
			Token: token,
		})
		return
	}

	// Hash new password
	passwordHash, err := auth.HashPassword(newPassword)
	if err != nil {
		log.Printf("[ERROR] HandleResetPasswordPost: Failed to hash password: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		s.resetPasswordTemplate.Execute(w, ResetPasswordPageData{
			Error: "An error occurred. Please try again.",
			Token: token,
		})
		return
	}

	// Update password
	err = s.datastore.Q.UpdateUserPasswordWithTimestamp(r.Context(), db.UpdateUserPasswordWithTimestampParams{
		PasswordHash: passwordHash,
		ID:           tokenRecord.UserID,
	})
	if err != nil {
		log.Printf("[ERROR] HandleResetPasswordPost: Failed to update password: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		s.resetPasswordTemplate.Execute(w, ResetPasswordPageData{
			Error: "An error occurred. Please try again.",
			Token: token,
		})
		return
	}

	// Mark token as used
	err = s.datastore.Q.MarkPasswordResetTokenUsed(r.Context(), tokenHash)
	if err != nil {
		// Log but don't fail - password was already updated
		log.Printf("[ERROR] HandleResetPasswordPost: Failed to mark token as used: %v", err)
	}

	log.Printf("[DEBUG] HandleResetPasswordPost: Password reset successfully for user %s", tokenRecord.Username)

	// Redirect to login with success message
	http.Redirect(w, r, "/oauth/login?password_reset=true", http.StatusFound)
}

// HandleForgotUsernameGet godoc
// @Summary      Show forgot username page
// @Description  Displays the forgot username form
// @Tags         authentication
// @Produce      html
// @Success      200 {string} string "HTML forgot username page"
// @Router       /forgot-username [get]
func (s *Server) HandleForgotUsernameGet(w http.ResponseWriter, r *http.Request) {
	s.forgotUsernameTemplate.Execute(w, ForgotPasswordPageData{})
}

// HandleForgotUsernamePost godoc
// @Summary      Request username reminder
// @Description  Sends a username reminder email if the account exists
// @Tags         authentication
// @Accept       application/x-www-form-urlencoded
// @Produce      html
// @Param        email formData string true "Email address"
// @Success      200 {string} string "HTML forgot username page with success message"
// @Router       /forgot-username [post]
func (s *Server) HandleForgotUsernamePost(w http.ResponseWriter, r *http.Request) {
	emailAddr := r.FormValue("email")

	if emailAddr == "" {
		w.WriteHeader(http.StatusBadRequest)
		s.forgotUsernameTemplate.Execute(w, ForgotPasswordPageData{
			Error: "Email address is required",
		})
		return
	}

	// Always show success message to prevent email enumeration
	successMsg := "If an account with that email exists, we've sent your username."

	// Look up user by email
	user, err := s.datastore.Q.GetUserByEmail(r.Context(), emailAddr)
	if err != nil {
		// User not found - still show success message (no email enumeration)
		log.Printf("[DEBUG] HandleForgotUsernamePost: No user found for email %s", emailAddr)
		s.forgotUsernameTemplate.Execute(w, ForgotPasswordPageData{
			Success: successMsg,
		})
		return
	}

	// Send username reminder email
	err = s.emailSender.Send(r.Context(), email.Message{
		To:      emailAddr,
		Subject: "Your Username Reminder",
		HTML: fmt.Sprintf(`
			<h2>Username Reminder</h2>
			<p>You requested a reminder of your username for your account.</p>
			<p>Your username is: <strong>%s</strong></p>
			<p>If you didn't request this, you can safely ignore this email.</p>
		`, user.Username),
		Text: fmt.Sprintf(`
Username Reminder

You requested a reminder of your username for your account.

Your username is: %s

If you didn't request this, you can safely ignore this email.
		`, user.Username),
	})
	if err != nil {
		log.Printf("[ERROR] HandleForgotUsernamePost: Failed to send email: %v", err)
		// Still show success to prevent enumeration, but log the error
	}

	log.Printf("[DEBUG] HandleForgotUsernamePost: Username reminder email sent to %s", emailAddr)
	s.forgotUsernameTemplate.Execute(w, ForgotPasswordPageData{
		Success: successMsg,
	})
}
