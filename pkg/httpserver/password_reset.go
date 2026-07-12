package httpserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/eswan18/identity/pkg/auth"
	"github.com/eswan18/identity/pkg/db"
	"github.com/eswan18/identity/pkg/email"
	"github.com/eswan18/identity/pkg/views"
	"github.com/google/uuid"
)

const (
	passwordResetTokenTTL = 1 * time.Hour
	passwordResetTokenLen = 32 // bytes

	// asyncMailWorkTimeout bounds the background token-generation/store/email-send
	// work kicked off by HandleForgotPasswordPost and HandleForgotUsernamePost. It
	// must be independent of the request context, which is cancelled the moment the
	// handler returns the unified response to the client.
	asyncMailWorkTimeout = 30 * time.Second
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

// renderForgotPassword renders the forgot-password page, injecting the CSRF token.
func (s *Server) renderForgotPassword(w http.ResponseWriter, r *http.Request, data views.ForgotPasswordView) {
	data.CSRFToken = s.ensureCSRFToken(w, r)
	_ = views.ForgotPassword(data).Render(r.Context(), w)
}

// renderForgotUsername renders the forgot-username page, injecting the CSRF token.
func (s *Server) renderForgotUsername(w http.ResponseWriter, r *http.Request, data views.ForgotPasswordView) {
	data.CSRFToken = s.ensureCSRFToken(w, r)
	_ = views.ForgotUsername(data).Render(r.Context(), w)
}

// renderResetPassword renders the reset-password page, injecting the CSRF token.
func (s *Server) renderResetPassword(w http.ResponseWriter, r *http.Request, data views.ResetPasswordView) {
	data.CSRFToken = s.ensureCSRFToken(w, r)
	_ = views.ResetPassword(data).Render(r.Context(), w)
}

// HandleForgotPasswordGet godoc
// @Summary      Show forgot password page
// @Description  Displays the forgot password form
// @Tags         authentication
// @Produce      html
// @Success      200 {string} string "HTML forgot password page"
// @Router       /forgot-password [get]
func (s *Server) HandleForgotPasswordGet(w http.ResponseWriter, r *http.Request) {
	s.renderForgotPassword(w, r, views.ForgotPasswordView{})
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
		s.renderForgotPassword(w, r, views.ForgotPasswordView{
			Error: "Email address is required",
		})
		return
	}

	// Always show success message to prevent email enumeration. This response
	// must be returned identically (same status, same body, roughly the same
	// latency) whether or not an account exists for emailAddr - see the
	// goroutine dispatch below for why the account-exists case doesn't do any
	// of its work inline.
	successMsg := "If an account with that email exists, we've sent a password reset link."

	// Look up user by email
	user, err := s.datastore.Q.GetUserByEmail(r.Context(), emailAddr)
	if err != nil {
		// User not found - still show success message (no email enumeration)
		s.debugf("HandleForgotPasswordPost: No user found for email %s", emailAddr)
		s.renderForgotPassword(w, r, views.ForgotPasswordView{
			Success: successMsg,
		})
		return
	}

	// The account exists. Generating the token, storing its hash, and sending
	// the email are all deferred to a background goroutine so that this
	// request returns the same unified response at the same latency as the
	// "account not found" branch above - doing this work inline would let an
	// attacker distinguish existing from non-existing accounts purely by
	// response time, and any failure here would otherwise have to surface as
	// a distinct error response, leaking existence a second way.
	//
	// The goroutine must not use r.Context(): that context is cancelled as
	// soon as this handler returns, which happens immediately after this
	// point, and would abort the DB write / email send mid-flight. Instead it
	// gets its own detached context with a bounded timeout. Only plain values
	// (userID, username, emailAddr, issuer) are captured, not any
	// request-scoped mutable state.
	go s.sendPasswordResetEmailAsync(user.ID, emailAddr)

	s.renderForgotPassword(w, r, views.ForgotPasswordView{
		Success: successMsg,
	})
}

// sendPasswordResetEmailAsync generates a password reset token, stores its
// hash, and emails the reset link. It runs in a background goroutine kicked
// off by HandleForgotPasswordPost after the HTTP response has already been
// sent, so it uses its own detached, timeout-bounded context rather than the
// (by-then-cancelled) request context. Any failure is logged server-side
// only: by design, nothing here can change what the client already saw.
func (s *Server) sendPasswordResetEmailAsync(userID uuid.UUID, emailAddr string) {
	ctx, cancel := context.WithTimeout(context.Background(), asyncMailWorkTimeout)
	defer cancel()

	// Generate token
	rawToken, tokenHash, err := generateResetToken()
	if err != nil {
		log.Printf("[ERROR] HandleForgotPasswordPost: Failed to generate token for %s: %v", emailAddr, err)
		return
	}

	// Store token hash in database
	expiresAt := time.Now().Add(passwordResetTokenTTL)
	err = s.datastore.Q.CreatePasswordResetToken(ctx, db.CreatePasswordResetTokenParams{
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		log.Printf("[ERROR] HandleForgotPasswordPost: Failed to store token for %s: %v", emailAddr, err)
		return
	}

	// Send password reset email
	resetURL := fmt.Sprintf("%s/oauth/reset-password?token=%s", s.config.JWTIssuer, rawToken)
	err = s.emailSender.Send(ctx, email.Message{
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
		log.Printf("[ERROR] HandleForgotPasswordPost: Failed to send email to %s: %v", emailAddr, err)
		return
	}

	s.debugf("HandleForgotPasswordPost: Password reset email sent to %s", emailAddr)
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
		s.renderResetPassword(w, r, views.ResetPasswordView{
			Error: "Invalid password reset link.",
		})
		return
	}

	// Validate token exists and is not expired
	tokenHash := hashToken(token)
	_, err := s.datastore.Q.GetPasswordResetTokenByHash(r.Context(), tokenHash)
	if err != nil {
		s.debugf("HandleResetPasswordGet: Invalid or expired token")
		w.WriteHeader(http.StatusBadRequest)
		s.renderResetPassword(w, r, views.ResetPasswordView{
			Error: "This password reset link is invalid or has expired. Please request a new one.",
		})
		return
	}

	s.renderResetPassword(w, r, views.ResetPasswordView{
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
		s.renderResetPassword(w, r, views.ResetPasswordView{
			Error: "Invalid password reset link.",
		})
		return
	}

	if newPassword == "" || confirmPassword == "" {
		w.WriteHeader(http.StatusBadRequest)
		s.renderResetPassword(w, r, views.ResetPasswordView{
			Error: "All fields are required.",
			Token: token,
		})
		return
	}

	if newPassword != confirmPassword {
		w.WriteHeader(http.StatusBadRequest)
		s.renderResetPassword(w, r, views.ResetPasswordView{
			Error: "Passwords do not match.",
			Token: token,
		})
		return
	}

	// Validate and get token record first (need username for password validation)
	tokenHash := hashToken(token)
	tokenRecord, err := s.datastore.Q.GetPasswordResetTokenByHash(r.Context(), tokenHash)
	if err != nil {
		s.debugf("HandleResetPasswordPost: Invalid or expired token")
		w.WriteHeader(http.StatusBadRequest)
		s.renderResetPassword(w, r, views.ResetPasswordView{
			Error: "This password reset link is invalid or has expired. Please request a new one.",
		})
		return
	}

	// Validate password requirements
	if err := auth.ValidatePassword(newPassword, tokenRecord.Username); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		s.renderResetPassword(w, r, views.ResetPasswordView{
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
		s.renderResetPassword(w, r, views.ResetPasswordView{
			Error: "An error occurred. Please try again.",
			Token: token,
		})
		return
	}

	// Atomically mark the token as used BEFORE updating the password. The WHERE
	// clause guards against TOCTOU: if another request already consumed this
	// token between the earlier lookup and now, the UPDATE affects 0 rows and
	// we refuse to reset. Ordering matters — if we updated the password first
	// and the mark-used write failed or raced, the token would remain valid and
	// could reset the password again. Failing the reset when the user has to
	// request a new token is strictly safer than allowing replay.
	rowsAffected, err := s.datastore.Q.MarkPasswordResetTokenUsed(r.Context(), tokenHash)
	if err != nil {
		log.Printf("[ERROR] HandleResetPasswordPost: Failed to mark token as used: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		s.renderResetPassword(w, r, views.ResetPasswordView{
			Error: "An error occurred. Please try again.",
			Token: token,
		})
		return
	}
	if rowsAffected == 0 {
		w.WriteHeader(http.StatusBadRequest)
		s.renderResetPassword(w, r, views.ResetPasswordView{
			Error: "This password reset link is invalid or has expired. Please request a new one.",
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
		s.renderResetPassword(w, r, views.ResetPasswordView{
			Error: "An error occurred. Please try again.",
			Token: token,
		})
		return
	}

	s.debugf("HandleResetPasswordPost: Password reset successfully for user %s", tokenRecord.Username)

	// A password reset is a credential change: log the user out everywhere.
	// Revoke all OAuth tokens and delete all sessions for this user, same as
	// HandleChangePasswordPost and account deactivation do. There's no active
	// session tied to this request (the user isn't logged in during a reset),
	// so there's no cookie to clear here.
	userIDNullable := uuid.NullUUID{UUID: tokenRecord.UserID, Valid: true}
	if err := s.datastore.Q.RevokeAllUserTokens(r.Context(), userIDNullable); err != nil {
		log.Printf("[ERROR] HandleResetPasswordPost: Failed to revoke tokens: %v", err)
		// Continue anyway - the password was already reset successfully.
	}
	if err := s.datastore.Q.DeleteAllUserSessions(r.Context(), tokenRecord.UserID); err != nil {
		log.Printf("[ERROR] HandleResetPasswordPost: Failed to delete sessions: %v", err)
		// Continue anyway - the password was already reset successfully.
	}

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
	s.renderForgotUsername(w, r, views.ForgotPasswordView{})
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
		s.renderForgotUsername(w, r, views.ForgotPasswordView{
			Error: "Email address is required",
		})
		return
	}

	// Always show success message to prevent email enumeration. As with
	// HandleForgotPasswordPost, this response must look and take the same
	// time whether or not the account exists.
	successMsg := "If an account with that email exists, we've sent your username."

	// Look up user by email
	user, err := s.datastore.Q.GetUserByEmail(r.Context(), emailAddr)
	if err != nil {
		// User not found - still show success message (no email enumeration)
		s.debugf("HandleForgotUsernamePost: No user found for email %s", emailAddr)
		s.renderForgotUsername(w, r, views.ForgotPasswordView{
			Success: successMsg,
		})
		return
	}

	// Send the username reminder in the background for the same reason
	// HandleForgotPasswordPost defers its email send: keep the response
	// timing and content identical to the account-not-found case, and never
	// let an email-send failure surface as a different HTTP response. Uses a
	// detached context since r.Context() is cancelled once this handler
	// returns (which happens right after this call).
	go s.sendUsernameReminderEmailAsync(user.Username, emailAddr)

	s.renderForgotUsername(w, r, views.ForgotPasswordView{
		Success: successMsg,
	})
}

// sendUsernameReminderEmailAsync emails the username reminder. It runs in a
// background goroutine kicked off by HandleForgotUsernamePost after the HTTP
// response has already been sent, so it uses its own detached,
// timeout-bounded context rather than the (by-then-cancelled) request
// context. Failures are logged server-side only.
func (s *Server) sendUsernameReminderEmailAsync(username, emailAddr string) {
	ctx, cancel := context.WithTimeout(context.Background(), asyncMailWorkTimeout)
	defer cancel()

	err := s.emailSender.Send(ctx, email.Message{
		To:      emailAddr,
		Subject: "Your Username Reminder",
		HTML: fmt.Sprintf(`
			<h2>Username Reminder</h2>
			<p>You requested a reminder of your username for your account.</p>
			<p>Your username is: <strong>%s</strong></p>
			<p>If you didn't request this, you can safely ignore this email.</p>
		`, username),
		Text: fmt.Sprintf(`
Username Reminder

You requested a reminder of your username for your account.

Your username is: %s

If you didn't request this, you can safely ignore this email.
		`, username),
	})
	if err != nil {
		log.Printf("[ERROR] HandleForgotUsernamePost: Failed to send email to %s: %v", emailAddr, err)
		return
	}

	s.debugf("HandleForgotUsernamePost: Username reminder email sent to %s", emailAddr)
}
