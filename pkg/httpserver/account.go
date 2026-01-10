package httpserver

import (
	"log"
	"net/http"

	"github.com/eswan18/identity/pkg/auth"
	"github.com/eswan18/identity/pkg/db"
)

// HandleRoot godoc
// @Summary      Root redirect
// @Description  Redirects to account settings if logged in, or login page if not
// @Tags         navigation
// @Success      302 {string} string "Redirect to appropriate page"
// @Router       / [get]
func (s *Server) HandleRoot(w http.ResponseWriter, r *http.Request) {
	_, err := s.getUserFromSession(r)
	if err != nil {
		// Not logged in, redirect to login
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}
	// Logged in, redirect to account settings
	http.Redirect(w, r, "/oauth/account-settings", http.StatusFound)
}

// HandleAccountSettingsGet godoc
// @Summary      Show account settings page
// @Description  Displays the account settings page where users can view their account info and change their password
// @Tags         account
// @Produce      html
// @Success      200 {string} string "HTML account settings page"
// @Failure      401 {string} string "Unauthorized - no valid session"
// @Router       /account-settings [get]
func (s *Server) HandleAccountSettingsGet(w http.ResponseWriter, r *http.Request) {
	// Get user from session
	user, err := s.getUserFromSession(r)
	if err != nil {
		log.Printf("[DEBUG] HandleAccountSettingsGet: Failed to get user from session: %v", err)
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}

	s.accountSettingsTemplate.Execute(w, AccountSettingsPageData{
		Username: user.Username,
		Email:    user.Email,
	})
}

// HandleAccountSettingsPost godoc
// @Summary      Update account settings
// @Description  Processes account settings form submission (currently supports password change)
// @Tags         account
// @Accept       application/x-www-form-urlencoded
// @Produce      html
// @Param        current_password formData string true "Current password for verification"
// @Param        new_password     formData string true "New password"
// @Param        confirm_password formData string true "Confirm new password"
// @Success      200 {string} string "HTML account settings page with success message"
// @Failure      400 {string} string "Invalid request - passwords don't match"
// @Failure      401 {string} string "Unauthorized - invalid current password"
// @Router       /account-settings [post]
func (s *Server) HandleAccountSettingsPost(w http.ResponseWriter, r *http.Request) {
	// Get user from session
	user, err := s.getUserFromSession(r)
	if err != nil {
		log.Printf("[DEBUG] HandleAccountSettingsPost: Failed to get user from session: %v", err)
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}

	currentPassword := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")
	confirmPassword := r.FormValue("confirm_password")

	pageData := AccountSettingsPageData{
		Username: user.Username,
		Email:    user.Email,
	}

	// Validate that all fields are provided
	if currentPassword == "" || newPassword == "" || confirmPassword == "" {
		s.renderAccountSettingsError(w, http.StatusBadRequest, "All password fields are required", pageData)
		return
	}

	// Validate that new password and confirm password match
	if newPassword != confirmPassword {
		s.renderAccountSettingsError(w, http.StatusBadRequest, "New passwords do not match", pageData)
		return
	}

	// Validate current password
	valid, err := auth.VerifyPassword(currentPassword, user.PasswordHash)
	if err != nil {
		log.Printf("[ERROR] HandleAccountSettingsPost: Failed to verify password: %v", err)
		s.renderAccountSettingsError(w, http.StatusInternalServerError, "An error occurred", pageData)
		return
	}
	if !valid {
		s.renderAccountSettingsError(w, http.StatusUnauthorized, "Current password is incorrect", pageData)
		return
	}

	// Hash new password
	newPasswordHash, err := auth.HashPassword(newPassword)
	if err != nil {
		log.Printf("[ERROR] HandleAccountSettingsPost: Failed to hash new password: %v", err)
		s.renderAccountSettingsError(w, http.StatusInternalServerError, "An error occurred", pageData)
		return
	}

	// Update password in database
	err = s.datastore.Q.UpdateUserPassword(r.Context(), db.UpdateUserPasswordParams{
		PasswordHash: newPasswordHash,
		ID:           user.ID,
	})
	if err != nil {
		log.Printf("[ERROR] HandleAccountSettingsPost: Failed to update password: %v", err)
		s.renderAccountSettingsError(w, http.StatusInternalServerError, "An error occurred", pageData)
		return
	}

	log.Printf("[DEBUG] HandleAccountSettingsPost: Password updated successfully for user: %s", user.Username)

	// Render success
	pageData.Success = "Password updated successfully"
	s.accountSettingsTemplate.Execute(w, pageData)
}

// getUserFromSession retrieves the authenticated user from the session cookie
func (s *Server) getUserFromSession(r *http.Request) (db.AuthUser, error) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return db.AuthUser{}, err
	}

	session, err := s.datastore.Q.GetSession(r.Context(), cookie.Value)
	if err != nil {
		return db.AuthUser{}, err
	}

	user, err := s.datastore.Q.GetUserByID(r.Context(), session.UserID)
	if err != nil {
		return db.AuthUser{}, err
	}

	return user, nil
}

// renderAccountSettingsError renders the account settings page with an error message
func (s *Server) renderAccountSettingsError(w http.ResponseWriter, statusCode int, errorMsg string, pageData AccountSettingsPageData) {
	w.WriteHeader(statusCode)
	pageData.Error = errorMsg
	err := s.accountSettingsTemplate.Execute(w, pageData)
	if err != nil {
		log.Printf("[ERROR] renderAccountSettingsError: Failed to render template: %v", err)
		http.Error(w, "An error occurred", http.StatusInternalServerError)
	}
}
