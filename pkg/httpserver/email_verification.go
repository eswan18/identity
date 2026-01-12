package httpserver

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/eswan18/identity/pkg/db"
	"github.com/eswan18/identity/pkg/email"
	"github.com/google/uuid"
)

const (
	tokenTypeVerification = "verification"
	verificationTokenTTL  = 24 * time.Hour
)

// generateVerificationToken generates a random token and returns both the raw token
// (to send to user) and its SHA-256 hash (to store in DB).
func generateVerificationToken() (rawToken string, tokenHash string, err error) {
	// Generate 32 bytes of random data
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate random token: %w", err)
	}

	// Encode to hex for URL-safe token
	rawToken = hex.EncodeToString(tokenBytes)

	// Hash for storage
	hash := sha256.Sum256([]byte(rawToken))
	tokenHash = hex.EncodeToString(hash[:])

	return rawToken, tokenHash, nil
}

// hashToken hashes a raw token for lookup.
func hashToken(rawToken string) string {
	hash := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(hash[:])
}

// sendVerificationEmail generates a token and sends a verification email to the user.
func (s *Server) sendVerificationEmail(ctx context.Context, userID uuid.UUID, userEmail, username string) error {
	// Delete any existing verification tokens for this user
	if err := s.datastore.Q.DeleteUserEmailTokens(ctx, db.DeleteUserEmailTokensParams{
		UserID:    userID,
		TokenType: tokenTypeVerification,
	}); err != nil {
		log.Printf("Warning: failed to delete existing email tokens: %v", err)
	}

	// Generate new token
	rawToken, tokenHash, err := generateVerificationToken()
	if err != nil {
		return fmt.Errorf("failed to generate verification token: %w", err)
	}

	// Store hashed token in DB
	expiresAt := time.Now().Add(verificationTokenTTL)
	if err := s.datastore.Q.CreateEmailToken(ctx, db.CreateEmailTokenParams{
		UserID:    userID,
		TokenHash: tokenHash,
		TokenType: tokenTypeVerification,
		ExpiresAt: expiresAt,
	}); err != nil {
		return fmt.Errorf("failed to store verification token: %w", err)
	}

	// Build verification URL
	verifyURL := fmt.Sprintf("%s/oauth/verify-email?token=%s", s.config.JWTIssuer, rawToken)

	// Send email
	msg := email.Message{
		To:      userEmail,
		Subject: "Verify your email address",
		HTML:    buildVerificationEmailHTML(username, verifyURL),
		Text:    buildVerificationEmailText(username, verifyURL),
	}

	if err := s.emailSender.Send(ctx, msg); err != nil {
		return fmt.Errorf("failed to send verification email: %w", err)
	}

	return nil
}

func buildVerificationEmailHTML(username, verifyURL string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <h1 style="color: #1a1a1a;">Verify your email address</h1>
    <p>Hi %s,</p>
    <p>Please click the button below to verify your email address:</p>
    <p style="margin: 30px 0;">
        <a href="%s" style="background-color: #4F46E5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">Verify Email</a>
    </p>
    <p>Or copy and paste this link into your browser:</p>
    <p style="word-break: break-all; color: #666;">%s</p>
    <p>This link will expire in 24 hours.</p>
    <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
    <p style="color: #666; font-size: 14px;">If you didn't create an account, you can safely ignore this email.</p>
</body>
</html>`, username, verifyURL, verifyURL)
}

func buildVerificationEmailText(username, verifyURL string) string {
	return fmt.Sprintf(`Verify your email address

Hi %s,

Please click the link below to verify your email address:

%s

This link will expire in 24 hours.

If you didn't create an account, you can safely ignore this email.
`, username, verifyURL)
}

// HandleVerifyEmail handles the email verification link click.
func (s *Server) HandleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		s.renderError(w, http.StatusBadRequest, "Invalid Verification Link", "The verification link is invalid or malformed.", "")
		return
	}

	// Hash the token for lookup
	tokenHash := hashToken(token)

	// Look up the token
	emailToken, err := s.datastore.Q.GetEmailToken(r.Context(), db.GetEmailTokenParams{
		TokenHash: tokenHash,
		TokenType: tokenTypeVerification,
	})
	if err != nil {
		log.Printf("Email verification failed - token not found: %v", err)
		s.renderError(w, http.StatusBadRequest, "Invalid or Expired Link", "This verification link is invalid, has already been used, or has expired. Please request a new verification email.", "")
		return
	}

	// Mark the token as used
	if err := s.datastore.Q.MarkEmailTokenUsed(r.Context(), emailToken.ID); err != nil {
		log.Printf("Failed to mark email token as used: %v", err)
		// Continue anyway - the verification should still succeed
	}

	// Mark the user's email as verified
	if err := s.datastore.Q.SetEmailVerified(r.Context(), emailToken.UserID); err != nil {
		log.Printf("Failed to set email verified: %v", err)
		s.renderError(w, http.StatusInternalServerError, "Verification Failed", "An error occurred while verifying your email. Please try again later.", "")
		return
	}

	// Redirect to login with success message
	http.Redirect(w, r, "/oauth/login?email_verified=true", http.StatusFound)
}

// HandleResendVerification handles requests to resend the verification email.
func (s *Server) HandleResendVerification(w http.ResponseWriter, r *http.Request) {
	// Get the current user from session
	user, err := s.getUserFromSession(r)
	if err != nil {
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}

	// Check if already verified
	if user.EmailVerified {
		http.Redirect(w, r, "/oauth/account-settings?success=email_already_verified", http.StatusFound)
		return
	}

	// Send verification email
	if err := s.sendVerificationEmail(r.Context(), user.ID, user.Email, user.Username); err != nil {
		log.Printf("Failed to send verification email: %v", err)
		http.Redirect(w, r, "/oauth/account-settings?error=email_send_failed", http.StatusFound)
		return
	}

	http.Redirect(w, r, "/oauth/account-settings?success=verification_sent", http.StatusFound)
}

// renderError renders the error page with the given parameters.
func (s *Server) renderError(w http.ResponseWriter, statusCode int, title, message, redirectURI string) {
	w.WriteHeader(statusCode)
	if err := s.errorTemplate.Execute(w, ErrorPageData{
		Title:       title,
		Message:     message,
		RedirectURI: redirectURI,
	}); err != nil {
		http.Error(w, "An error occurred", http.StatusInternalServerError)
	}
}
