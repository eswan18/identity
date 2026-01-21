package httpserver

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/eswan18/identity/pkg/auth"
	"github.com/eswan18/identity/pkg/db"
	"github.com/google/uuid"
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
	// Get user from session - including inactive users so they can see their account settings
	user, err := s.getUserFromSessionIncludingInactive(r)
	if err != nil {
		log.Printf("[DEBUG] HandleAccountSettingsGet: Failed to get user from session: %v", err)
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}

	var success, errorMsg string
	switch r.URL.Query().Get("success") {
	case "verification_sent":
		success = "Verification email sent. Please check your inbox."
	case "email_already_verified":
		success = "Your email is already verified."
	}
	switch r.URL.Query().Get("error") {
	case "email_send_failed":
		errorMsg = "Failed to send verification email. Please try again later."
	}
	// Legacy query params
	if r.URL.Query().Get("reactivated") == "true" {
		success = "Your account has been reactivated."
	} else if r.URL.Query().Get("mfa_enabled") == "true" {
		success = "Two-factor authentication has been enabled."
	} else if r.URL.Query().Get("mfa_disabled") == "true" {
		success = "Two-factor authentication has been disabled."
	}

	s.accountSettingsTemplate.Execute(w, AccountSettingsPageData{
		Username:      user.Username,
		Email:         user.Email,
		IsInactive:    !user.IsActive,
		MfaEnabled:    user.MfaEnabled,
		EmailVerified: user.EmailVerified,
		Success:       success,
		Error:         errorMsg,
	})
}

// HandleChangePasswordGet godoc
// @Summary      Show change password page
// @Description  Displays the change password form
// @Tags         account
// @Produce      html
// @Success      200 {string} string "HTML change password page"
// @Failure      401 {string} string "Unauthorized - no valid session"
// @Router       /change-password [get]
func (s *Server) HandleChangePasswordGet(w http.ResponseWriter, r *http.Request) {
	_, err := s.getUserFromSession(r)
	if err != nil {
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}
	s.changePasswordTemplate.Execute(w, ChangePasswordPageData{})
}

// HandleChangePasswordPost godoc
// @Summary      Update password
// @Description  Processes password change form submission
// @Tags         account
// @Accept       application/x-www-form-urlencoded
// @Produce      html
// @Param        current_password formData string true "Current password for verification"
// @Param        new_password     formData string true "New password"
// @Param        confirm_password formData string true "Confirm new password"
// @Success      200 {string} string "HTML change password page with success message"
// @Failure      400 {string} string "Invalid request - passwords don't match"
// @Failure      401 {string} string "Unauthorized - invalid current password"
// @Router       /change-password [post]
func (s *Server) HandleChangePasswordPost(w http.ResponseWriter, r *http.Request) {
	user, err := s.getUserFromSession(r)
	if err != nil {
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}

	currentPassword := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")
	confirmPassword := r.FormValue("confirm_password")

	// Validate that all fields are provided
	if currentPassword == "" || newPassword == "" || confirmPassword == "" {
		s.renderChangePasswordError(w, http.StatusBadRequest, "All password fields are required")
		return
	}

	// Validate that new password and confirm password match
	if newPassword != confirmPassword {
		s.renderChangePasswordError(w, http.StatusBadRequest, "New passwords do not match")
		return
	}

	// Validate new password requirements
	if err := auth.ValidatePassword(newPassword, user.Username); err != nil {
		s.renderChangePasswordError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Validate current password
	valid, err := auth.VerifyPassword(currentPassword, user.PasswordHash)
	if err != nil {
		log.Printf("[ERROR] HandleChangePasswordPost: Failed to verify password: %v", err)
		s.renderChangePasswordError(w, http.StatusInternalServerError, "An error occurred")
		return
	}
	if !valid {
		s.renderChangePasswordError(w, http.StatusUnauthorized, "Current password is incorrect")
		return
	}

	// Hash new password
	newPasswordHash, err := auth.HashPassword(newPassword)
	if err != nil {
		log.Printf("[ERROR] HandleChangePasswordPost: Failed to hash new password: %v", err)
		s.renderChangePasswordError(w, http.StatusInternalServerError, "An error occurred")
		return
	}

	// Update password in database
	err = s.datastore.Q.UpdateUserPasswordWithTimestamp(r.Context(), db.UpdateUserPasswordWithTimestampParams{
		PasswordHash: newPasswordHash,
		ID:           user.ID,
	})
	if err != nil {
		log.Printf("[ERROR] HandleChangePasswordPost: Failed to update password: %v", err)
		s.renderChangePasswordError(w, http.StatusInternalServerError, "An error occurred")
		return
	}

	log.Printf("[DEBUG] HandleChangePasswordPost: Password updated successfully for user: %s", user.Username)
	s.changePasswordTemplate.Execute(w, ChangePasswordPageData{Success: "Password updated successfully"})
}

// HandleChangeUsernameGet godoc
// @Summary      Show change username page
// @Description  Displays the change username form
// @Tags         account
// @Produce      html
// @Success      200 {string} string "HTML change username page"
// @Failure      401 {string} string "Unauthorized - no valid session"
// @Router       /change-username [get]
func (s *Server) HandleChangeUsernameGet(w http.ResponseWriter, r *http.Request) {
	user, err := s.getUserFromSession(r)
	if err != nil {
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}
	s.changeUsernameTemplate.Execute(w, ChangeUsernamePageData{CurrentUsername: user.Username})
}

// HandleChangeUsernamePost godoc
// @Summary      Update username
// @Description  Processes username change form submission
// @Tags         account
// @Accept       application/x-www-form-urlencoded
// @Produce      html
// @Param        new_username formData string true "New username"
// @Param        password     formData string true "Password for verification"
// @Success      200 {string} string "HTML change username page with success message"
// @Failure      400 {string} string "Invalid request"
// @Failure      401 {string} string "Unauthorized - invalid password"
// @Router       /change-username [post]
func (s *Server) HandleChangeUsernamePost(w http.ResponseWriter, r *http.Request) {
	user, err := s.getUserFromSession(r)
	if err != nil {
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}

	newUsername := r.FormValue("new_username")
	password := r.FormValue("password")

	pageData := ChangeUsernamePageData{CurrentUsername: user.Username}

	// Validate that all fields are provided
	if newUsername == "" || password == "" {
		pageData.Error = "All fields are required"
		w.WriteHeader(http.StatusBadRequest)
		s.changeUsernameTemplate.Execute(w, pageData)
		return
	}

	// Validate password
	valid, err := auth.VerifyPassword(password, user.PasswordHash)
	if err != nil {
		log.Printf("[ERROR] HandleChangeUsernamePost: Failed to verify password: %v", err)
		pageData.Error = "An error occurred"
		w.WriteHeader(http.StatusInternalServerError)
		s.changeUsernameTemplate.Execute(w, pageData)
		return
	}
	if !valid {
		pageData.Error = "Password is incorrect"
		w.WriteHeader(http.StatusUnauthorized)
		s.changeUsernameTemplate.Execute(w, pageData)
		return
	}

	// Check if username is already taken
	_, err = s.datastore.Q.GetUserByUsername(r.Context(), newUsername)
	if err == nil {
		pageData.Error = "Username is already taken"
		w.WriteHeader(http.StatusBadRequest)
		s.changeUsernameTemplate.Execute(w, pageData)
		return
	}

	// Update username in database
	err = s.datastore.Q.UpdateUserUsername(r.Context(), db.UpdateUserUsernameParams{
		Username: newUsername,
		ID:       user.ID,
	})
	if err != nil {
		log.Printf("[ERROR] HandleChangeUsernamePost: Failed to update username: %v", err)
		pageData.Error = "An error occurred"
		w.WriteHeader(http.StatusInternalServerError)
		s.changeUsernameTemplate.Execute(w, pageData)
		return
	}

	log.Printf("[DEBUG] HandleChangeUsernamePost: Username updated successfully from %s to %s", user.Username, newUsername)
	s.changeUsernameTemplate.Execute(w, ChangeUsernamePageData{
		Success:         "Username updated successfully",
		CurrentUsername: newUsername,
	})
}

// HandleChangeEmailGet godoc
// @Summary      Show change email page
// @Description  Displays the change email form
// @Tags         account
// @Produce      html
// @Success      200 {string} string "HTML change email page"
// @Failure      401 {string} string "Unauthorized - no valid session"
// @Router       /change-email [get]
func (s *Server) HandleChangeEmailGet(w http.ResponseWriter, r *http.Request) {
	user, err := s.getUserFromSession(r)
	if err != nil {
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}
	s.changeEmailTemplate.Execute(w, ChangeEmailPageData{CurrentEmail: user.Email})
}

// HandleChangeEmailPost godoc
// @Summary      Update email
// @Description  Processes email change form submission
// @Tags         account
// @Accept       application/x-www-form-urlencoded
// @Produce      html
// @Param        new_email formData string true "New email address"
// @Param        password  formData string true "Password for verification"
// @Success      200 {string} string "HTML change email page with success message"
// @Failure      400 {string} string "Invalid request"
// @Failure      401 {string} string "Unauthorized - invalid password"
// @Router       /change-email [post]
func (s *Server) HandleChangeEmailPost(w http.ResponseWriter, r *http.Request) {
	user, err := s.getUserFromSession(r)
	if err != nil {
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}

	newEmail := r.FormValue("new_email")
	password := r.FormValue("password")

	pageData := ChangeEmailPageData{CurrentEmail: user.Email}

	// Validate that all fields are provided
	if newEmail == "" || password == "" {
		pageData.Error = "All fields are required"
		w.WriteHeader(http.StatusBadRequest)
		s.changeEmailTemplate.Execute(w, pageData)
		return
	}

	// Validate password
	valid, err := auth.VerifyPassword(password, user.PasswordHash)
	if err != nil {
		log.Printf("[ERROR] HandleChangeEmailPost: Failed to verify password: %v", err)
		pageData.Error = "An error occurred"
		w.WriteHeader(http.StatusInternalServerError)
		s.changeEmailTemplate.Execute(w, pageData)
		return
	}
	if !valid {
		pageData.Error = "Password is incorrect"
		w.WriteHeader(http.StatusUnauthorized)
		s.changeEmailTemplate.Execute(w, pageData)
		return
	}

	// Check if email is already taken
	_, err = s.datastore.Q.GetUserByEmail(r.Context(), newEmail)
	if err == nil {
		pageData.Error = "Email is already taken"
		w.WriteHeader(http.StatusBadRequest)
		s.changeEmailTemplate.Execute(w, pageData)
		return
	}

	// Update email in database
	err = s.datastore.Q.UpdateUserEmail(r.Context(), db.UpdateUserEmailParams{
		Email: newEmail,
		ID:    user.ID,
	})
	if err != nil {
		log.Printf("[ERROR] HandleChangeEmailPost: Failed to update email: %v", err)
		pageData.Error = "An error occurred"
		w.WriteHeader(http.StatusInternalServerError)
		s.changeEmailTemplate.Execute(w, pageData)
		return
	}

	log.Printf("[DEBUG] HandleChangeEmailPost: Email updated successfully from %s to %s", user.Email, newEmail)
	s.changeEmailTemplate.Execute(w, ChangeEmailPageData{
		Success:      "Email updated successfully",
		CurrentEmail: newEmail,
	})
}

// HandleEditProfileGet godoc
// @Summary      Show edit profile page
// @Description  Displays the edit profile form with current profile data
// @Tags         account
// @Produce      html
// @Success      200 {string} string "HTML edit profile page"
// @Failure      401 {string} string "Unauthorized - no valid session"
// @Router       /edit-profile [get]
func (s *Server) HandleEditProfileGet(w http.ResponseWriter, r *http.Request) {
	user, err := s.getUserFromSession(r)
	if err != nil {
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}
	s.editProfileTemplate.Execute(w, EditProfilePageData{
		Name:       user.Name.String,
		GivenName:  user.GivenName.String,
		FamilyName: user.FamilyName.String,
		Locale:     user.Locale.String,
		Zoneinfo:   user.Zoneinfo.String,
	})
}

// HandleEditProfilePost godoc
// @Summary      Update profile
// @Description  Processes profile edit form submission
// @Tags         account
// @Accept       application/x-www-form-urlencoded
// @Produce      html
// @Param        name        formData string false "Full display name"
// @Param        given_name  formData string false "Given/first name"
// @Param        family_name formData string false "Family/last name"
// @Param        locale      formData string false "Preferred locale (e.g., en-US)"
// @Param        zoneinfo    formData string false "Timezone (e.g., America/Chicago)"
// @Success      200 {string} string "HTML edit profile page with success message"
// @Failure      401 {string} string "Unauthorized - no valid session"
// @Router       /edit-profile [post]
func (s *Server) HandleEditProfilePost(w http.ResponseWriter, r *http.Request) {
	user, err := s.getUserFromSession(r)
	if err != nil {
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}

	name := r.FormValue("name")
	givenName := r.FormValue("given_name")
	familyName := r.FormValue("family_name")
	locale := r.FormValue("locale")
	zoneinfo := r.FormValue("zoneinfo")

	// Update profile in database
	err = s.datastore.Q.UpdateUserProfile(r.Context(), db.UpdateUserProfileParams{
		Name:       toNullString(name),
		GivenName:  toNullString(givenName),
		FamilyName: toNullString(familyName),
		Locale:     toNullString(locale),
		Zoneinfo:   toNullString(zoneinfo),
		ID:         user.ID,
	})
	if err != nil {
		log.Printf("[ERROR] HandleEditProfilePost: Failed to update profile: %v", err)
		s.editProfileTemplate.Execute(w, EditProfilePageData{
			Error:      "An error occurred",
			Name:       name,
			GivenName:  givenName,
			FamilyName: familyName,
			Locale:     locale,
			Zoneinfo:   zoneinfo,
		})
		return
	}

	log.Printf("[DEBUG] HandleEditProfilePost: Profile updated successfully for user: %s", user.Username)
	s.editProfileTemplate.Execute(w, EditProfilePageData{
		Success:    "Profile updated successfully",
		Name:       name,
		GivenName:  givenName,
		FamilyName: familyName,
		Locale:     locale,
		Zoneinfo:   zoneinfo,
	})
}

// toNullString converts a string to sql.NullString
func toNullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{Valid: false}
	}
	return sql.NullString{String: s, Valid: true}
}

// renderChangePasswordError renders the change password page with an error message
func (s *Server) renderChangePasswordError(w http.ResponseWriter, statusCode int, errorMsg string) {
	w.WriteHeader(statusCode)
	s.changePasswordTemplate.Execute(w, ChangePasswordPageData{Error: errorMsg})
}

// getUserFromSession retrieves the authenticated user from the session cookie
// This only returns active users - deactivated users will get an error
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

// getUserFromSessionIncludingInactive retrieves the authenticated user from the session cookie
// including deactivated users. This is used for the account settings page so deactivated
// users can still access their account settings.
func (s *Server) getUserFromSessionIncludingInactive(r *http.Request) (db.AuthUser, error) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return db.AuthUser{}, err
	}

	session, err := s.datastore.Q.GetSession(r.Context(), cookie.Value)
	if err != nil {
		return db.AuthUser{}, err
	}

	user, err := s.datastore.Q.GetUserByIDIncludingInactive(r.Context(), session.UserID)
	if err != nil {
		return db.AuthUser{}, err
	}

	return user, nil
}

// HandleDeactivateAccountPost godoc
// @Summary      Deactivate user account
// @Description  Deactivates the user's account by setting is_active to false
// @Tags         account
// @Accept       application/x-www-form-urlencoded
// @Produce      html
// @Param        password formData string true "Password for verification"
// @Success      302 {string} string "Redirect to login page after deactivation"
// @Failure      400 {string} string "Invalid request"
// @Failure      401 {string} string "Unauthorized - invalid password"
// @Router       /deactivate-account [post]
func (s *Server) HandleDeactivateAccountPost(w http.ResponseWriter, r *http.Request) {
	user, err := s.getUserFromSessionIncludingInactive(r)
	if err != nil {
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}

	password := r.FormValue("password")

	// Validate that password is provided
	if password == "" {
		s.accountSettingsTemplate.Execute(w, AccountSettingsPageData{
			Username: user.Username,
			Email:    user.Email,
			Error:    "Password is required to deactivate your account",
		})
		return
	}

	// Validate password
	valid, err := auth.VerifyPassword(password, user.PasswordHash)
	if err != nil {
		log.Printf("[ERROR] HandleDeactivateAccountPost: Failed to verify password: %v", err)
		s.accountSettingsTemplate.Execute(w, AccountSettingsPageData{
			Username: user.Username,
			Email:    user.Email,
			Error:    "An error occurred",
		})
		return
	}
	if !valid {
		w.WriteHeader(http.StatusUnauthorized)
		s.accountSettingsTemplate.Execute(w, AccountSettingsPageData{
			Username: user.Username,
			Email:    user.Email,
			Error:    "Password is incorrect",
		})
		return
	}

	// Deactivate the user
	err = s.datastore.Q.DeactivateUser(r.Context(), user.ID)
	if err != nil {
		log.Printf("[ERROR] HandleDeactivateAccountPost: Failed to deactivate user: %v", err)
		s.accountSettingsTemplate.Execute(w, AccountSettingsPageData{
			Username: user.Username,
			Email:    user.Email,
			Error:    "An error occurred while deactivating your account",
		})
		return
	}

	// Revoke all OAuth tokens for this user
	userIDNullable := uuid.NullUUID{UUID: user.ID, Valid: true}
	if err := s.datastore.Q.RevokeAllUserTokens(r.Context(), userIDNullable); err != nil {
		log.Printf("[ERROR] HandleDeactivateAccountPost: Failed to revoke tokens: %v", err)
		// Continue anyway - account is deactivated, tokens will be rejected on use
	}

	log.Printf("[DEBUG] HandleDeactivateAccountPost: User %s deactivated successfully", user.Username)

	// Delete the session and clear the cookie
	cookie, _ := r.Cookie("session_id")
	if cookie != nil {
		s.datastore.Q.DeleteSession(r.Context(), cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	// Redirect to login with a message
	http.Redirect(w, r, "/oauth/login?deactivated=true", http.StatusFound)
}

// HandleReactivateAccountPost godoc
// @Summary      Reactivate user account
// @Description  Reactivates the user's account by setting is_active to true
// @Tags         account
// @Accept       application/x-www-form-urlencoded
// @Produce      html
// @Param        password formData string true "Password for verification"
// @Success      302 {string} string "Redirect to account settings after reactivation"
// @Failure      400 {string} string "Invalid request"
// @Failure      401 {string} string "Unauthorized - invalid password"
// @Router       /reactivate-account [post]
func (s *Server) HandleReactivateAccountPost(w http.ResponseWriter, r *http.Request) {
	user, err := s.getUserFromSessionIncludingInactive(r)
	if err != nil {
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}

	password := r.FormValue("password")

	// Validate that password is provided
	if password == "" {
		s.accountSettingsTemplate.Execute(w, AccountSettingsPageData{
			Username:   user.Username,
			Email:      user.Email,
			IsInactive: !user.IsActive,
			Error:      "Password is required to reactivate your account",
		})
		return
	}

	// Validate password
	valid, err := auth.VerifyPassword(password, user.PasswordHash)
	if err != nil {
		log.Printf("[ERROR] HandleReactivateAccountPost: Failed to verify password: %v", err)
		s.accountSettingsTemplate.Execute(w, AccountSettingsPageData{
			Username:   user.Username,
			Email:      user.Email,
			IsInactive: !user.IsActive,
			Error:      "An error occurred",
		})
		return
	}
	if !valid {
		w.WriteHeader(http.StatusUnauthorized)
		s.accountSettingsTemplate.Execute(w, AccountSettingsPageData{
			Username:   user.Username,
			Email:      user.Email,
			IsInactive: !user.IsActive,
			Error:      "Password is incorrect",
		})
		return
	}

	// Reactivate the user
	err = s.datastore.Q.ReactivateUser(r.Context(), user.ID)
	if err != nil {
		log.Printf("[ERROR] HandleReactivateAccountPost: Failed to reactivate user: %v", err)
		s.accountSettingsTemplate.Execute(w, AccountSettingsPageData{
			Username:   user.Username,
			Email:      user.Email,
			IsInactive: !user.IsActive,
			Error:      "An error occurred while reactivating your account",
		})
		return
	}

	log.Printf("[DEBUG] HandleReactivateAccountPost: User %s reactivated successfully", user.Username)

	// Redirect to account settings with success message
	http.Redirect(w, r, "/oauth/account-settings?reactivated=true", http.StatusFound)
}
